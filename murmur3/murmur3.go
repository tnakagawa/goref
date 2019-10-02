package murmur3

// https://github.com/bitcoin/bitcoin/blob/880bc728b43f1ea3df690512087590270cf35601/src/hash.cpp

import (
	"encoding/binary"
)

// Hash ...
func Hash(seed uint32, data []byte) uint32 {
	// The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
	h1 := seed
	c1 := uint32(0xcc9e2d51)
	c2 := uint32(0x1b873593)

	nblocks := len(data) / 4

	//----------
	// body
	blocks := data

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(blocks[i*4:])

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17) // ROTL32(k1, 15);
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19) // ROTL32(h1, 13);
		h1 = h1*5 + 0xe6546b64
	}

	//----------
	// tail
	tail := data[nblocks*4:]

	k1 := uint32(0)

	switch len(tail) & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17) // ROTL32(k1, 15);
		k1 *= c2
		h1 ^= k1
	}

	//----------
	// finalization
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return h1
}
