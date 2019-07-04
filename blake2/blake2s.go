package blake2

import (
	"encoding/binary"
	"errors"
)

// Blake2s :
type Blake2s struct {
	nn    int         // Hash bytes   | 1 <= nn <= 32    |
	ll    uint64      // Input bytes  | 0 <= ll < 2**64  |
	IV    [8]uint32   // Initialization Vector
	SIGMA [10][16]int // Message word schedule
	h     [8]uint32   // Hash value
	cash  []byte      // Cash
}

// NewBlake2s :
func NewBlake2s(nn int, key []byte) (*Blake2s, error) {
	if nn < 1 || 32 < nn {
		return nil, errors.New("blake2b: invalid hash size")
	}
	kk := len(key)
	if 32 < kk {
		return nil, errors.New("blake2b: invalid key size")
	}
	b2s := &Blake2s{}
	b2s.nn = nn
	b2s.ll = uint64(0)
	b2s.IV = [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	b2s.SIGMA = [10][16]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	}
	copy(b2s.h[:], b2s.IV[:])
	// Parameter block p[0]
	b2s.h[0] ^= 0x01010000 ^ (uint32(kk) << 8) ^ uint32(nn)
	b2s.cash = []byte{}
	if kk > 0 {
		b2s.cash = append(b2s.cash, key...)
		for len(b2s.cash) < 64 {
			b2s.cash = append(b2s.cash, 0)
		}
	}
	return b2s, nil
}

func (b2s *Blake2s) g(v [16]uint32, a, b, c, d int, x, y uint32) [16]uint32 {
	v[a] = v[a] + v[b] + x
	v[d] = ((v[d] ^ v[a]) >> 16) | ((v[d] ^ v[a]) << 16)
	v[c] = v[c] + v[d]
	v[b] = ((v[b] ^ v[c]) >> 12) | ((v[b] ^ v[c]) << 20)
	v[a] = v[a] + v[b] + y
	v[d] = ((v[d] ^ v[a]) >> 8) | ((v[d] ^ v[a]) << 24)
	v[c] = v[c] + v[d]
	v[b] = ((v[b] ^ v[c]) >> 7) | ((v[b] ^ v[c]) << 25)
	return v
}

func (b2s *Blake2s) f(m [16]uint32, f bool) {
	v := [16]uint32{}
	copy(v[0:], b2s.h[:])
	copy(v[8:], b2s.IV[:])
	v[12] ^= uint32(b2s.ll & 0xffffffff)
	v[13] ^= uint32(b2s.ll >> 32)
	if f {
		v[14] ^= 0xffffffff
	}
	for i := 0; i < 10; i++ {
		s := b2s.SIGMA[i%10]
		v = b2s.g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		v = b2s.g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		v = b2s.g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		v = b2s.g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		v = b2s.g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		v = b2s.g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		v = b2s.g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		v = b2s.g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		b2s.h[i] ^= v[i] ^ v[i+8]
	}
}

// Update :
func (b2s *Blake2s) Update(bs []byte) {
	for _, b := range bs {
		if len(b2s.cash) == 64 {
			b2s.ll += 64
			m := [16]uint32{}
			for i := range m {
				m[i] = binary.LittleEndian.Uint32(b2s.cash[i*4 : i*4+4])
			}
			b2s.f(m, false)
			b2s.cash = []byte{}
		}
		b2s.cash = append(b2s.cash, b)
	}
}

// Final :
func (b2s *Blake2s) Final() []byte {
	size := uint64(len(b2s.cash))
	b2s.ll += size
	for len(b2s.cash) < 64 {
		b2s.cash = append(b2s.cash, 0)
	}
	m := [16]uint32{}
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(b2s.cash[i*4 : i*4+4])
	}
	b2s.f(m, true)
	bs := make([]byte, 32)
	for i, h := range b2s.h {
		binary.LittleEndian.PutUint32(bs[i*4:], h)
		if (i * 4) > b2s.nn {
			break
		}
	}
	return bs[0:b2s.nn]
}
