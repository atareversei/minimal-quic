package pool

import (
	"github.com/atareversei/minimal-quic/internal/packet"
	"sync"
)

const DefaultBufferSize = 1500

type BufferPool struct {
	size int
	pool *sync.Pool
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: &sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

func (bp *BufferPool) Get() *[]byte {
	return bp.pool.Get().(*[]byte)
}

func (bp *BufferPool) Put(b *[]byte) {
	if cap(*b) != bp.size {
		return
	}

	tmp := (*b)[:bp.size]
	*b = tmp
	bp.pool.Put(b)
}

type PacketPool struct {
	pool *sync.Pool
}

func NewPacketPool() *PacketPool {
	return &PacketPool{
		pool: &sync.Pool{
			New: func() any {
				return &packet.Packet{}
			},
		},
	}
}

func (pp *PacketPool) Get() *packet.Packet {
	p := pp.pool.Get().(*packet.Packet)

	p.Header = nil
	p.Payload = nil

	return p
}

func (pp *PacketPool) Put(p *packet.Packet) {
	p.Header = nil
	p.Payload = nil
}

type HeaderPool struct {
	pool *sync.Pool
}

func NewHeaderPool() *HeaderPool {
	return &HeaderPool{
		pool: &sync.Pool{
			New: func() any {
				return &packet.PacketHeader{}
			},
		},
	}
}

func (hp *HeaderPool) Get() *packet.PacketHeader {
	h := hp.pool.Get().(*packet.PacketHeader)

	h.HeaderLen = 0
	h.IsLongHeader = false
	h.Type = 0
	h.Version = 0
	h.DCID = nil
	h.SCID = nil
	h.PacketNumberLength = 0
	h.PacketNumber = 0
	h.IsPayloadLengthPresent = false
	h.PayloadLength = 0

	return h
}

func (hp *HeaderPool) Put(h *packet.PacketHeader) {
	h.HeaderLen = 0
	h.IsLongHeader = false
	h.Type = 0
	h.Version = 0
	h.DCID = nil
	h.SCID = nil
	h.PacketNumberLength = 0
	h.PacketNumber = 0
	h.IsPayloadLengthPresent = false
	h.PayloadLength = 0

	hp.pool.Put(h)
}

type Pools struct {
	Buffers *BufferPool
	Headers *HeaderPool
	Packets *PacketPool
}

func NewPools() Pools {
	return Pools{
		Buffers: NewBufferPool(DefaultBufferSize),
		Packets: NewPacketPool(),
		Headers: NewHeaderPool(),
	}
}
