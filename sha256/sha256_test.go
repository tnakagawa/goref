package sha256_test

// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
// SHA Test Vectors for Hashing Byte-Oriented Messages

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/tnakagawa/goref/sha256"
)

type Sha256Test struct {
	Len int
	Msg string
	MD  string
}

func TestVectorShort(t *testing.T) {
	bs, err := ioutil.ReadFile("./TestSha256Short.json")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var tests []Sha256Test
	err = json.Unmarshal(bs, &tests)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	for _, test := range tests {
		md, _ := hex.DecodeString(test.MD)
		msg, _ := hex.DecodeString(test.Msg)
		if test.Len == 0 {
			msg = []byte{}
		}
		h := sha256.Digest(msg)
		if !reflect.DeepEqual(md, h) {
			t.Errorf("%x %x", md, h)
			return
		}
	}
}

func TestVectorLong(t *testing.T) {
	bs, err := ioutil.ReadFile("./TestSha256Long.json")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var tests []Sha256Test
	err = json.Unmarshal(bs, &tests)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	for _, test := range tests {
		md, _ := hex.DecodeString(test.MD)
		msg, _ := hex.DecodeString(test.Msg)
		if test.Len == 0 {
			msg = []byte{}
		}
		h := sha256.Digest(msg)
		if !reflect.DeepEqual(md, h) {
			t.Errorf("%x %x", md, h)
			return
		}
	}
}
