package sha256

// https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf

import (
	"encoding/binary"
)

// H0 is the initial hash value.
var H0 = []uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

// K is sixty-four constant 32-bit words.
var K = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

// ROTR is the rotate right (circular right shift) operation.
func ROTR(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// SHR is the right shift operation.
func SHR(x uint32, n uint) uint32 {
	return x >> n
}

// Ch ...
func Ch(x, y, z uint32) uint32 {
	return (x & y) ^ (z &^ x)
}

// Maj ...
func Maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// SIGMA0 is a SIGMA 0.
func SIGMA0(x uint32) uint32 {
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
}

// SIGMA1 is a SIGMA 1.
func SIGMA1(x uint32) uint32 {
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
}

func sigma0(x uint32) uint32 {
	return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)
}

func sigma1(x uint32) uint32 {
	return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)
}

func padding(msg []byte) []byte {
	len := len(msg)
	tmp := make([]byte, 64)
	tmp[0] = 0x80
	bs := make([]byte, len)
	copy(bs, msg)
	if len%64 < 56 {
		bs = append(bs, tmp[0:56-len%64]...)
	} else {
		bs = append(bs, tmp[0:64+56-len%64]...)
	}
	bits := uint64(len * 8)
	size := make([]byte, 8)
	binary.BigEndian.PutUint64(size, bits)
	bs = append(bs, size...)
	return bs
}

func compute(msg []byte) []byte {
	N := len(msg) / 64
	W := make([]uint32, 64)
	H := make([]uint32, len(H0))
	copy(H, H0)
	for i := 1; i <= N; i++ {
		for t := 0; t < 64; t++ {
			if t < 16 {
				p := (i-1)*64 + t*4
				W[t] = binary.BigEndian.Uint32(msg[p : p+4])
			} else {
				W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
			}
		}
		a := H[0]
		b := H[1]
		c := H[2]
		d := H[3]
		e := H[4]
		f := H[5]
		g := H[6]
		h := H[7]
		for t := 0; t < 64; t++ {
			T1 := h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t]
			T2 := SIGMA0(a) + Maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + T1
			d = c
			c = b
			b = a
			a = T1 + T2
		}
		H[0] = a + H[0]
		H[1] = b + H[1]
		H[2] = c + H[2]
		H[3] = d + H[3]
		H[4] = e + H[4]
		H[5] = f + H[5]
		H[6] = g + H[6]
		H[7] = h + H[7]
	}
	hash := make([]byte, 32)
	for i, h := range H {
		binary.BigEndian.PutUint32(hash[i*4:], h)
	}
	return hash
}

// Digest ...
func Digest(bs []byte) []byte {
	return compute(padding(bs))
}
