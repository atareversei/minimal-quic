package internal

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// VarInt represents a decoded QUIC variable-length integer.
type VarInt struct {
	Value  uint64
	Length int
}

// PacketHeader is a simplified representation of QUIC packet header
type PacketHeader struct {
	IsLongHeader           bool
	Type                   uint8
	Version                uint32
	DCID                   []byte
	SCID                   []byte
	PacketNumber           uint64
	PacketNumberLength     int
	HeaderLen              int
	PayloadLength          uint64
	IsPayloadLengthPresent bool
}

// Packet holds the raw payload bytes and the header.
type Packet struct {
	Header  *PacketHeader
	Payload []byte
}

type Frame struct {
	Type byte
	Data []byte
}

type ParsedPacket struct {
	Addr        *net.UDPAddr
	Packet      Packet
	ReceiveTime time.Time
}

var (
	ErrNotEnoughData  = errors.New("not enough bytes")
	ErrVarIntTooLarge = errors.New("variant length is larger than available bytes")
	ErrMalformed      = errors.New("malformed packet")
)

// DecodeVarInt decodes a QUIC VarInt from the front of data.
// Returns the decoded VarInt and an error if buffer is too small.
func DecodeVarInt(data []byte) (VarInt, error) {
	if len(data) == 0 {
		return VarInt{}, ErrNotEnoughData
	}

	first := data[0]
	prefix := first >> 6

	switch prefix {
	case 0:
		val := uint64(first & 0x3F)
		return VarInt{Value: val, Length: 1}, nil
	case 1:
		if len(data) < 2 {
			return VarInt{}, ErrVarIntTooLarge
		}
		val := uint64(first&0x3F)<<8 | uint64(data[1])
		return VarInt{Value: val, Length: 2}, nil
	case 2:
		if len(data) < 4 {
			return VarInt{}, ErrVarIntTooLarge
		}
		val := uint64(first&0x3F)<<24 |
			uint64(data[1])<<16 |
			uint64(data[2])<<8 |
			uint64(data[3])
		return VarInt{Value: val, Length: 4}, nil
	case 3:
		if len(data) < 8 {
			return VarInt{}, ErrVarIntTooLarge
		}
		val := uint64(first&0x3F)<<56 |
			uint64(data[1])<<48 |
			uint64(data[2])<<40 |
			uint64(data[3])<<32 |
			uint64(data[4])<<24 |
			uint64(data[5])<<16 |
			uint64(data[6])<<8 |
			uint64(data[7])
		return VarInt{Value: val, Length: 8}, nil
	default:
		return VarInt{}, ErrMalformed
	}
}

// DecodePacketHeader decodes the QUIC header from data and returns the PacketHeader
// and the number of bytes consumed up to (but not including) the packet number.
// For long headers it parses Version, DCID, SCID, TokenLength (skips token),
// and PayloadLength (VarInt). For short headers it returns a minimal header
// with HeaderLen = 1 (caller must handle DCID by context).
func DecodePacketHeader(data []byte) (*PacketHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrNotEnoughData
	}

	first := data[0]
	isLong := (first >> 7) == 1
	pnLen := int(first&0x03) + 1

	h := &PacketHeader{
		IsLongHeader:       isLong,
		PacketNumberLength: pnLen,
		HeaderLen:          1,
	}

	if !isLong {
		return h, h.HeaderLen, nil
	}

	idx := 1

	if len(data) < idx+4 {
		return nil, 0, ErrNotEnoughData
	}
	h.Version = binary.BigEndian.Uint32(data[idx : idx+4])
	idx += 4

	if len(data) < idx+1 {
		return nil, 0, ErrNotEnoughData
	}
	dcidLen := int(data[idx])
	idx++
	if len(data) < idx+dcidLen {
		return nil, 0, ErrNotEnoughData
	}
	if dcidLen > 0 {
		h.DCID = append([]byte(nil), data[idx:idx+dcidLen]...)
	} else {
		h.DCID = nil
	}
	idx += dcidLen

	if len(data) < idx+1 {
		return nil, 0, ErrNotEnoughData
	}
	scidLen := int(data[idx])
	idx++
	if len(data) < idx+scidLen {
		return nil, 0, ErrNotEnoughData
	}
	if scidLen > 0 {
		h.SCID = append([]byte(nil), data[idx:idx+scidLen]...)
	} else {
		h.SCID = nil
	}
	idx += scidLen

	if len(data) < idx+1 {
		return nil, 0, ErrNotEnoughData
	}
	tokenVar, err := DecodeVarInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += tokenVar.Length

	tokenLen := int(tokenVar.Value)
	if len(data) < idx+tokenLen {
		return nil, 0, ErrNotEnoughData
	}
	idx += tokenLen

	if len(data) < idx+1 {
		return nil, 0, ErrNotEnoughData
	}
	lengthVar, err := DecodeVarInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	h.PayloadLength = lengthVar.Value
	h.IsPayloadLengthPresent = true
	idx += lengthVar.Length

	h.HeaderLen = idx
	return h, h.HeaderLen, nil
}

// DecodePacket decodes header and packet-number, returns a Packet with payload
// (payload is remaining bytes after packet number). The receiveTime/addr are
// set by the parser loop which constructs ParsedPacket.
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 1 {
		return nil, ErrNotEnoughData
	}

	h, headerLen, err := DecodePacketHeader(data)
	if err != nil {
		return nil, err
	}

	if len(data) < headerLen+h.PacketNumberLength {
		return nil, ErrNotEnoughData
	}

	pn := uint64(0)
	for i := 0; i < h.PacketNumberLength; i++ {
		pn = (pn << 8) | uint64(data[headerLen+1])
	}
	h.PacketNumber = pn

	payloadStart := headerLen + h.PacketNumberLength
	payload := append([]byte(nil), data[payloadStart:]...)

	pkt := &Packet{
		Header:  h,
		Payload: payload,
	}

	return pkt, nil
}
