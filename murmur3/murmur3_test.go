package murmur3_test

import (
	"encoding/hex"
	"testing"

	"github.com/tnakagawa/goref/murmur3"
)

func TestVector(t *testing.T) {
	tvs := getTestVector()
	for _, tv := range tvs {
		h := murmur3.Hash(tv.Seed, tv.Data)
		if h != tv.Expected {
			t.Errorf("0x%08x 0x%08x", h, tv.Expected)
		}
	}
}

type Test struct {
	Expected uint32
	Seed     uint32
	Data     []byte
}

func getTestVector() []Test {
	tvs := []Test{}

	// https://github.com/bitcoin/bitcoin/blob/master/src/test/hash_tests.cpp#L18

	// T(0x00000000U, 0x00000000, "");
	tv := Test{}
	tv.Expected = 0x00000000
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("")
	tvs = append(tvs, tv)
	// T(0x6a396f08U, 0xFBA4C795, "");
	tv = Test{}
	tv.Expected = 0x6a396f08
	tv.Seed = 0xFBA4C795
	tv.Data, _ = hex.DecodeString("")
	tvs = append(tvs, tv)
	// T(0x81f16f39U, 0xffffffff, "");
	tv = Test{}
	tv.Expected = 0x81f16f39
	tv.Seed = 0xffffffff
	tv.Data, _ = hex.DecodeString("")
	tvs = append(tvs, tv)

	// T(0x514e28b7U, 0x00000000, "00");
	tv = Test{}
	tv.Expected = 0x514e28b7
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("00")
	tvs = append(tvs, tv)
	// T(0xea3f0b17U, 0xFBA4C795, "00");
	tv = Test{}
	tv.Expected = 0xea3f0b17
	tv.Seed = 0xFBA4C795
	tv.Data, _ = hex.DecodeString("00")
	tvs = append(tvs, tv)
	// T(0xfd6cf10dU, 0x00000000, "ff");
	tv = Test{}
	tv.Expected = 0xfd6cf10d
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("ff")
	tvs = append(tvs, tv)

	// T(0x16c6b7abU, 0x00000000, "0011");
	tv = Test{}
	tv.Expected = 0x16c6b7ab
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("0011")
	tvs = append(tvs, tv)
	// T(0x8eb51c3dU, 0x00000000, "001122");
	tv = Test{}
	tv.Expected = 0x8eb51c3d
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("001122")
	tvs = append(tvs, tv)
	// T(0xb4471bf8U, 0x00000000, "00112233");
	tv = Test{}
	tv.Expected = 0xb4471bf8
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("00112233")
	tvs = append(tvs, tv)
	// T(0xe2301fa8U, 0x00000000, "0011223344");
	tv = Test{}
	tv.Expected = 0xe2301fa8
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("0011223344")
	tvs = append(tvs, tv)
	// T(0xfc2e4a15U, 0x00000000, "001122334455");
	tv = Test{}
	tv.Expected = 0xfc2e4a15
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("001122334455")
	tvs = append(tvs, tv)
	// T(0xb074502cU, 0x00000000, "00112233445566");
	tv = Test{}
	tv.Expected = 0xb074502c
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("00112233445566")
	tvs = append(tvs, tv)
	// T(0x8034d2a0U, 0x00000000, "0011223344556677");
	tv = Test{}
	tv.Expected = 0x8034d2a0
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("0011223344556677")
	tvs = append(tvs, tv)
	// T(0xb4698defU, 0x00000000, "001122334455667788");
	tv = Test{}
	tv.Expected = 0xb4698def
	tv.Seed = 0x00000000
	tv.Data, _ = hex.DecodeString("001122334455667788")
	tvs = append(tvs, tv)

	return tvs
}
