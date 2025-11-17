package packet_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/atareversei/minimal-quic/internal/packet"
)

func TestDecodeVarInt_1Byte(t *testing.T) {
	// 1 byte: 00xxxxxx
	b := []byte{0x25} // 0b0010_0101 = 0x25
	v, err := packet.DecodeVarInt(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != 0x25 {
		t.Fatalf("expected 0x25, got %d", v.Value)
	}
	if v.Length != 1 {
		t.Fatalf("expected length 1, got %d", v.Length)
	}
}

func TestDecodeVarInt_2Byte(t *testing.T) {
	// 2 byte: 01xxxxxx
	b := []byte{0x40 | 0x01, 0x01} // 0x41, 0x01
	v, err := packet.DecodeVarInt(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := uint64(0x0101 & 0x3FFF)
	if v.Value != expected {
		t.Fatalf("expected %d, got %d", expected, v.Value)
	}
	if v.Length != 2 {
		t.Fatalf("expected length 2, got %d", v.Length)
	}
}

func TestDecodeVarInt_4Byte(t *testing.T) {
	// 4 byte: 10xxxxxx
	b := []byte{0x80 | 0x02, 0x11, 0x22, 0x33}
	v, err := packet.DecodeVarInt(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Length != 4 {
		t.Fatalf("expected length 4")
	}
	if v.Value == 0 {
		t.Fatalf("expected non-zero value")
	}
}

func TestDecodeVarInt_8Byte(t *testing.T) {
	// 8 byte: 11xxxxxx
	b := []byte{0xC0 | 0x03, 1, 2, 3, 4, 5, 6, 7}
	v, err := packet.DecodeVarInt(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Length != 8 {
		t.Fatalf("expected length 8")
	}
	if v.Value == 0 {
		t.Fatalf("expected non-zero value")
	}
}

// Construct a simple long header with:
// - First byte: Long header, PN length = 2 (=> low bits = 01)
// - Version: 0x12345678
// - DCID: length=4, value: [1,2,3,4]
// - SCID: length=3, value: [5,6,7]
// - Token length: VaInt=0 (1 byte: 00xxxxxx = 0)
// - Payload Length: VarInt=20 (1 byte fits)
// - Packet Number: 2 bytes: [0xAA, 0xBB]
// - Payload: "hello"
func makeLongHeaderPacket() []byte {
	buf := []byte{}

	// First byte: long header => top bit=1, PN length bits=01 => PN len=2
	first := byte(0xC0 | 0x01)
	buf = append(buf, first)

	// Version
	v := uint32(0x12345678)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, v)
	buf = append(buf, tmp...)

	// DCID
	buf = append(buf, byte(4))
	buf = append(buf, []byte{1, 2, 3, 4}...)

	// SCID
	buf = append(buf, byte(3))
	buf = append(buf, []byte{5, 6, 7}...)

	// Token length: 0
	buf = append(buf, byte(0x00))

	// Payload length: say 20 -> fits in single-byte varint
	buf = append(buf, byte(20))

	// Packet Number (2 bytes)
	buf = append(buf, 0xAA, 0xBB)

	// Payload
	buf = append(buf, []byte("hello")...)

	return buf
}

func TestDecodeHeader_Long(t *testing.T) {
	pkt := makeLongHeaderPacket()

	h, consumed, err := packet.DecodePacketHeader(pkt)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	if !h.IsLongHeader {
		t.Fatalf("expected long header")
	}
	if h.Version != 0x12345678 {
		t.Fatalf("wrong version: %x", h.Version)
	}
	if len(h.DCID) != 4 {
		t.Fatalf("DCID length mismatch")
	}
	if len(h.SCID) != 3 {
		t.Fatalf("SCID length mismatch")
	}
	if consumed != h.HeaderLen {
		t.Fatalf("consume mismatch: %d vs %d", consumed, h.HeaderLen)
	}
	if !h.IsPayloadLengthPresent {
		t.Fatalf("expected payload length present")
	}
	if h.PayloadLength != 20 {
		t.Fatalf("wrong payload length: %d", h.PayloadLength)
	}
	if h.PacketNumberLength != 2 {
		t.Fatalf("incorrect PN length")
	}
}

func TestDecodeHeader_Short(t *testing.T) {
	// Short header: top bit = 0
	pkt := []byte{0x45} // Lower bits specify PN length = (0x45 & 0x03)+1 = 2 bytes
	h, _, err := packet.DecodePacketHeader(pkt)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if h.IsLongHeader {
		t.Fatalf("expected short header")
	}
	if h.PacketNumberLength != 2 {
		t.Fatalf("expected PN length 2")
	}
}

func TestDecodePacket(t *testing.T) {
	data := makeLongHeaderPacket()

	pkt, err := packet.DecodePacket(data)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	if pkt.Header.PacketNumber != 0xAABB {
		t.Fatalf("wrong packet number: %#X", pkt.Header.PacketNumber)
	}

	// payload should be "hello"
	if string(pkt.Payload) != "hello" {
		t.Fatalf("unexpected payload: %s", pkt.Payload)
	}
}

func TestParsedPacketStruct(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	pp := packet.ParsedPacket{
		Addr:        addr,
		Packet:      &packet.Packet{},
		ReceiveTime: time.Now(),
	}

	if pp.Addr.IP.String() != "1.2.3.4" {
		t.Fatalf("address mismatch")
	}
}
