package ripemd160_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/tnakagawa/goref/ripemd160"
)

func Vector() [][][]byte {
	tests := [][][]byte{}
	h, _ := hex.DecodeString("9c1185a5c5e9fc54612808977ee8f548b2258d31")
	tests = append(tests, [][]byte{[]byte(""), h})
	h, _ = hex.DecodeString("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")
	tests = append(tests, [][]byte{[]byte("a"), h})
	h, _ = hex.DecodeString("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
	tests = append(tests, [][]byte{[]byte("abc"), h})
	h, _ = hex.DecodeString("5d0689ef49d2fae572b881b123a85ffa21595f36")
	tests = append(tests, [][]byte{[]byte("message digest"), h})
	h, _ = hex.DecodeString("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
	tests = append(tests, [][]byte{[]byte("abcdefghijklmnopqrstuvwxyz"), h})
	h, _ = hex.DecodeString("12a053384a9c0c88e405a06c27dcf49ada62eb2b")
	tests = append(tests, [][]byte{[]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), h})
	h, _ = hex.DecodeString("b0e20b6e3116640286ed3a87a5713079b21f5189")
	tests = append(tests, [][]byte{[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), h})
	h, _ = hex.DecodeString("9b752e45573d4b39f4dbd3323cab82bf63326bfb")
	tests = append(tests, [][]byte{[]byte("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), h})
	msg := make([]byte, 1000000)
	msg[0] = []byte("a")[0]
	for p := 1; p < len(msg); p *= 2 {
		copy(msg[p:], msg[:p])
	}
	h, _ = hex.DecodeString("52783243c1697bdbe16d37f97f68f08325dc1528")
	tests = append(tests, [][]byte{msg, h})
	return tests
}

func TestVector(t *testing.T) {
	tests := Vector()
	for _, test := range tests {
		h := ripemd160.Digest(test[0])
		if !reflect.DeepEqual(test[1], h) {
			t.Errorf("%x %x", test[1], h)
			return
		}
	}
}
