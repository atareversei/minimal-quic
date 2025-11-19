package parser

import (
	"errors"
	"github.com/atareversei/minimal-quic/internal/packet"
	"github.com/atareversei/minimal-quic/internal/pool"
)

// ParsePacket decodes a raw UDP packet into a ParsedPacket.
// It uses pools to avoid allocations where appropriate.
func ParsePacket(raw *packet.ReceivedPacket, pools *pool.Pools) (*packet.ParsedPacket, error) {
	pkt, err := packet.DecodePacket(raw.Data)
	if err != nil {
		return nil, err
	}

	frames, err := parseFrames(pkt.Payload)
	if err != nil {
		return nil, err
	}

	parsed := &packet.ParsedPacket{
		Addr:        raw.Addr,
		Packet:      pkt,
		ReceiveTime: raw.RcvTime,
	}

	parsed.Packet = pkt
	parsed.Frames = frames

	_ = pools

	return parsed, nil
}

func parseFrames(payload []byte) ([]packet.Frame, error) {
	var frames []packet.Frame
	i := 0
	for i < len(payload) {
		ft := payload[i]

		if ft == 0x00 {
			frames = append(frames, ft)
			i++
			continue
		}

		if ft == 0x02 {
			i++
			if i >= len(payload) {
				return frames, errors.New("truncated ack frame")
			}

			v, err := packet.DecodeVarInt(payload[i:])
			if err != nil {
				return frames, err
			}

			consumed := v.Length
			data := make([]byte, consumed)
			copy(data, payload[i:i+consumed])
			frames = append(frames, ft)
			i += consumed
			continue
		}

		if (ft & 0xF8) == 0x10 {
			sf, n, err := parserStreamFrame(payload[i:])
			if err != nil {
				return frames, err
			}
			frames = append(frames, sf)
			i += n
			continue
		}

		return frames, errors.New("unknown/unsupported frame type")
	}

	return frames, nil
}

// parseStreamFrame parses a simplified stream frame.
// Simplified format assumed:
// - 1 byte type (0x10..0x17)
// - VarInt streamID
// - VarInt offset
// - VarInt length
// - <length> bytes of data
func parserStreamFrame(b []byte) (*packet.StreamFrame, int, error) {
	if len(b) < 1 {
		return nil, 0, errors.New("truncated stream frame")
	}

	i := 1
	sidVar, err := packet.DecodeVarInt(b[i:])
	if err != nil {
		return nil, 0, err
	}
	i += sidVar.Length

	offVar, err := packet.DecodeVarInt(b[i:])
	if err != nil {
		return nil, 0, err
	}
	i += offVar.Length

	lenVar, err := packet.DecodeVarInt(b[i:])
	if err != nil {
		return nil, 0, err
	}
	i += offVar.Length

	length := int(lenVar.Value)
	if len(b) < i+length {
		return nil, 0, errors.New("stram frame truncated payload")
	}

	data := make([]byte, length)
	copy(data, b[i:i+length])
	i += length

	sf := &packet.StreamFrame{
		StreamID: sidVar.Value,
		Offset:   offVar.Value,
		Data:     data,
		Fin:      false,
	}

	return sf, i, nil
}

// parseAckFrame is not used in parseFrames (we parse minimal ACK inline).
// Provided for completeness if you want to expand ACK parsing.
func parseAckFrame(b []byte) (*packet.AckFrame, int, error) {
	if len(b) < 2 {
		return nil, 0, errors.New("truncated ack")
	}

	i := 1
	v, err := packet.DecodeVarInt(b[i:])
	if err != nil {
		return nil, 0, err
	}

	i += v.Length
	af := &packet.AckFrame{
		LargestAcked: v.Value,
		AckRanges:    nil,
	}

	return af, i, nil
}
