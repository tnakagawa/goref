package blake2

import (
	"encoding/binary"
	"errors"
)

// Blake2b :
type Blake2b struct {
	nn    int         // Hash bytes   | 1 <= nn <= 64    |
	ll    [2]uint64   // Input bytes  | 0 <= ll < 2**128 |
	IV    [8]uint64   // Initialization Vector
	SIGMA [10][16]int // Message word schedule
	h     [8]uint64   // Hash value
	cash  []byte      // Cash
}

// NewBlake2b :
func NewBlake2b(nn int, key []byte) (*Blake2b, error) {
	if nn < 1 || 64 < nn {
		return nil, errors.New("blake2b: invalid hash size")
	}
	kk := len(key)
	if 64 < kk {
		return nil, errors.New("blake2b: invalid key size")
	}
	b2b := &Blake2b{}
	b2b.nn = nn
	b2b.ll = [2]uint64{0, 0}
	b2b.IV = [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	b2b.SIGMA = [10][16]int{
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
	copy(b2b.h[:], b2b.IV[:])
	// Parameter block p[0]
	b2b.h[0] ^= 0x01010000 ^ (uint64(kk) << 8) ^ uint64(nn)
	b2b.cash = []byte{}
	if kk > 0 {
		b2b.cash = append(b2b.cash, key...)
		for len(b2b.cash) < 128 {
			b2b.cash = append(b2b.cash, 0)
		}
	}
	return b2b, nil
}

func (b2b *Blake2b) g(v [16]uint64, a, b, c, d int, x, y uint64) [16]uint64 {
	v[a] = v[a] + v[b] + x
	v[d] = ((v[d] ^ v[a]) >> 32) | ((v[d] ^ v[a]) << 32)
	v[c] = v[c] + v[d]
	v[b] = ((v[b] ^ v[c]) >> 24) | ((v[b] ^ v[c]) << 40)
	v[a] = v[a] + v[b] + y
	v[d] = ((v[d] ^ v[a]) >> 16) | ((v[d] ^ v[a]) << 48)
	v[c] = v[c] + v[d]
	v[b] = ((v[b] ^ v[c]) >> 63) | ((v[b] ^ v[c]) << 1)
	return v
}

func (b2b *Blake2b) f(m [16]uint64, f bool) {
	v := [16]uint64{}
	copy(v[0:], b2b.h[:])
	copy(v[8:], b2b.IV[:])
	v[12] ^= b2b.ll[0]
	v[13] ^= b2b.ll[1]
	if f {
		v[14] ^= 0xffffffffffffffff
	}
	for i := 0; i < 12; i++ {
		s := b2b.SIGMA[i%10]
		v = b2b.g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		v = b2b.g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		v = b2b.g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		v = b2b.g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		v = b2b.g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		v = b2b.g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		v = b2b.g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		v = b2b.g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		b2b.h[i] ^= v[i] ^ v[i+8]
	}
}

// Update :
func (b2b *Blake2b) Update(bs []byte) {
	for _, b := range bs {
		if len(b2b.cash) == 128 {
			b2b.ll[0] += 128
			if b2b.ll[0] < 128 {
				b2b.ll[1]++
			}
			m := [16]uint64{}
			for i := range m {
				m[i] = binary.LittleEndian.Uint64(b2b.cash[i*8 : i*8+8])
			}
			b2b.f(m, false)
			b2b.cash = []byte{}
		}
		b2b.cash = append(b2b.cash, b)
	}
}

// Final :
func (b2b *Blake2b) Final() []byte {
	size := uint64(len(b2b.cash))
	b2b.ll[0] += size
	if b2b.ll[0] < size {
		b2b.ll[1]++
	}
	for len(b2b.cash) < 128 {
		b2b.cash = append(b2b.cash, 0)
	}
	m := [16]uint64{}
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(b2b.cash[i*8 : i*8+8])
	}
	b2b.f(m, true)
	bs := make([]byte, 64)
	for i, h := range b2b.h {
		binary.LittleEndian.PutUint64(bs[i*8:], h)
		if (i * 8) > b2b.nn {
			break
		}
	}
	return bs[0:b2b.nn]
}
