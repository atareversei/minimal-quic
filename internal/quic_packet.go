package internal

// TODO: The minimal packet only includes DCID, SCID, packet number, and payload.
// TODO: No variable-length encoding, encryption, or authentication is implemented.
// TODO: Payload length is inferred from UDP packet length; real QUIC encodes length explicitly.
// TODO: No validation of packet numbers across multiple packets per connection.

import (
	"encoding/binary"
	"errors"
)

const MaxPayloadSize = 1024

type QuicPacket struct {
	DCID          uint64
	SCID          uint64
	PakcetNumber  uint32
	Payload       []byte
	PayloadLength uint64
}

// Encode writes the packet into buf and returns number of bytes written.
func (qp *QuicPacket) Encode(buf []byte) (int, error) {
	required := 8 + 8 + 4 + len(qp.Payload)
	if len(buf) < required {
		return 0, errors.New("buffer too small")
	}

	binary.BigEndian.PutUint64(buf[0:8], qp.DCID)
	binary.BigEndian.PutUint64(buf[8:16], qp.SCID)
	binary.BigEndian.PutUint32(buf[16:20], qp.PakcetNumber)
	copy(buf[20:], qp.Payload)

	return required, nil
}

// Decode parses buf into a new QuicPacket and returns it or an error.
func Decode(buf []byte) (*QuicPacket, error) {
	if len(buf) < 20 {
		return nil, errors.New("buffer too small")
	}

	pkt := &QuicPacket{}

	pkt.DCID = binary.BigEndian.Uint64(buf[0:8])
	pkt.SCID = binary.BigEndian.Uint64(buf[8:16])
	pkt.PakcetNumber = binary.BigEndian.Uint32(buf[16:20])

	payloadLength := len(buf) - 20
	if payloadLength > MaxPayloadSize {
		return nil, errors.New("payload too large")
	}

	if payloadLength > 0 {
		pkt.Payload = make([]byte, payloadLength)
		copy(pkt.Payload, buf[20:])
	}

	return pkt, nil
}
