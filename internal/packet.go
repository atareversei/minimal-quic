package internal

import (
	"errors"
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
	Version                int32
	DCID                   uint64
	SCID                   uint64
	PacketNumber           uint32
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

var (
	ErrNotEnoughData  = errors.New("not enough bytes")
	ErrVarIntTooLarge = errors.New("variant length is larger than available bytes")
	ErrMalformed      = errors.New("malformed packet")
)

// DecodeVarInt decodes a QUIC variant from the front of data.
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

//func DecodeQuicPacket(data []byte) (*Packet, error)
//func DecodeQuicPacketHeader(data []byte) (*PacketHeader, int, error)
