package ripemd160

import "encoding/binary"

// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
// https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf

// nonlinear functions at bit level: exor, mux, -, mux, -
func f(j int, x, y, z uint32) uint32 {
	// f(j, x, y, z) = x ⊕ y ⊕ z             ( 0 ≤ j ≤ 15)
	if 0 <= j && j <= 15 {
		return x ^ y ^ z
	}
	// f(j, x, y, z) = (x ∧ y) ∨ (¬x ∧ z)   (16 ≤ j ≤ 31)
	if 16 <= j && j <= 31 {
		return (x & y) | (^x & z)
	}
	// f(j, x, y, z) = (x ∨ ¬y) ⊕ z          (32 ≤ j ≤ 47)
	if 32 <= j && j <= 47 {
		return (x | ^y) ^ z
	}
	// f(j, x, y, z) = (x ∧ z) ∨ (y ∧ ¬z)   (48 ≤ j ≤ 63)
	if 48 <= j && j <= 63 {
		return (x & z) | (y & ^z)
	}
	// f(j, x, y, z) = x ⊕ (y ∨ ¬z)          (64 ≤ j ≤ 79)
	if 64 <= j && j <= 79 {
		return x ^ (y | ^z)
	}
	return 0
}

// K1 : K added constants (hexadecimal)
func K1(j int) uint32 {
	// K(j) = 00000000x (0 ≤ j ≤ 15)
	if 0 <= j && j <= 15 {
		return 0x00000000
	}
	// K(j) = 5A827999x (16 ≤ j ≤ 31)
	if 16 <= j && j <= 31 {
		return 0x5A827999
	}
	// K(j) = 6ED9EBA1x (32 ≤ j ≤ 47)
	if 32 <= j && j <= 47 {
		return 0x6ED9EBA1
	}
	// K(j) = 8F1BBCDCx (48 ≤ j ≤ 63)
	if 48 <= j && j <= 63 {
		return 0x8F1BBCDC
	}
	// K(j) = A953FD4Ex (64 ≤ j ≤ 79)
	if 64 <= j && j <= 79 {
		return 0xA953FD4E
	}
	return 0
}

// K2 : K' added constants (hexadecimal)
func K2(j int) uint32 {
	// K'(j) = 50A28BE6x (0 ≤ j ≤ 15)
	if 0 <= j && j <= 15 {
		return 0x50A28BE6
	}
	// K'(j) = 5C4DD124x (16 ≤ j ≤ 31)
	if 16 <= j && j <= 31 {
		return 0x5C4DD124
	}
	// K'(j) = 6D703EF3x (32 ≤ j ≤ 47)
	if 32 <= j && j <= 47 {
		return 0x6D703EF3
	}
	// K'(j) = 7A6D76E9x (48 ≤ j ≤ 63)
	if 48 <= j && j <= 63 {
		return 0x7A6D76E9
	}
	// K'(j) = 00000000x (64 ≤ j ≤ 79)
	if 64 <= j && j <= 79 {
		return 0x00000000
	}
	return 0
}

// r1 : r selection of message word
var r1 = []int{
	// r(j) = j (0 ≤ j ≤ 15)
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	// r(16..31) = 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	// r(32..47) = 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	// r(48..63) = 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	// r(64..79) = 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

// r2 : r' selection of message word
var r2 = []int{
	// r'(0..15) = 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	// r'(16..31) = 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	// r'(32..47) = 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	// r'(48..63) = 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	// r'(64..79) = 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

// s1 : s amount for rotate left (rol)
var s1 = []uint32{
	// s(0..15)  = 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	// s(16..31) = 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	// s(32..47) = 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	// s(48..63) = 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	// s(64..79) = 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

// s2 : s' amount for rotate left (rol)
var s2 = []uint32{
	// s'(0..15)  = 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	// s'(16..31) = 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	// s'(32..47) = 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	// s'(48..63) = 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	// s'(64..79) = 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

// rol_s denotes cyclic left shift (rotate) over s positions.
func rol(s, x uint32) uint32 {
	return (x << s) | (x >> (32 - s))
}

func padding(msg []byte) []byte {
	// https://tools.ietf.org/html/rfc1320
	// 3.1 Step 1. Append Padding Bits
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
	// 3.2 Step 2. Append Length
	bits := uint64(len * 8)
	size := make([]byte, 8)
	binary.LittleEndian.PutUint64(size, bits)
	bs = append(bs, size...)
	return bs
}

func compute(msg []byte) []byte {
	t := len(msg) / 64
	// initial value (hexadecimal)
	// h0 = 67452301x; h1 = EFCDAB89x; h2 = 98BADCFEx; h3 = 10325476x; h4 = C3D2E1F0x;
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)
	// RIPEMD-160: pseudo-code
	for i := 0; i < t; i++ {
		// let X = [];
		X := make([]uint32, 16)
		for t := 0; t < 16; t++ {
			p := i*64 + t*4
			X[t] = binary.LittleEndian.Uint32(msg[p : p+4])
		}
		// A := h0; B := h1; C := h2; D = h3; E = h4;
		A1 := h0
		B1 := h1
		C1 := h2
		D1 := h3
		E1 := h4
		// A' := h0; B' := h1; C' := h2; D' = h3; E' = h4;
		A2 := h0
		B2 := h1
		C2 := h2
		D2 := h3
		E2 := h4
		T := uint32(0)
		for j := 0; j < 80; j++ {
			// T := rol_s(j) (A 田 f(j, B, C, D) 田 Xi[r(j)] 田 K(j)) 田 E;
			T = ta(rol(s1[j], ta(ta(ta(A1, f(j, B1, C1, D1)), X[r1[j]]), K1(j))), E1)
			// A := E; E := D; D := rol_10(C); C := B; B := T;
			A1 = E1
			E1 = D1
			D1 = rol(10, C1)
			C1 = B1
			B1 = T
			// T := rol_s'(j) (A'  田 f(79 - j, B', C', D')  田 Xi[r'(j)] 田 K'(j)) 田 E';
			T = ta(rol(s2[j], ta(ta(ta(A2, f(79-j, B2, C2, D2)), X[r2[j]]), K2(j))), E2)
			// A' := E'; E' := D'; D' := rol_10(C'); C' := B'; B' := T;
			A2 = E2
			E2 = D2
			D2 = rol(10, C2)
			C2 = B2
			B2 = T
		}
		// T := h1 田 C 田 D'; h1 := h2 田 D 田 E'; h2 := h3 田 E 田 A_;
		T = ta(ta(h1, C1), D2)
		h1 = ta(ta(h2, D1), E2)
		h2 = ta(ta(h3, E1), A2)
		// h3 := h4 田 A 田 B'; h4 := h0 田 B 田 C_; h0 := T;
		h3 = ta(ta(h4, A1), B2)
		h4 = ta(ta(h0, B1), C2)
		h0 = T
	}
	hash := make([]byte, 20)
	binary.LittleEndian.PutUint32(hash[0:], h0)
	binary.LittleEndian.PutUint32(hash[4:], h1)
	binary.LittleEndian.PutUint32(hash[8:], h2)
	binary.LittleEndian.PutUint32(hash[12:], h3)
	binary.LittleEndian.PutUint32(hash[16:], h4)
	return hash
}

func ta(x, y uint32) uint32 {
	return x + y
}

// Digest ...
func Digest(msg []byte) []byte {
	return compute(padding(msg))
}
