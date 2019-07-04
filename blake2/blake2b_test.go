package blake2_test

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/tnakagawa/goref/blake2"
)

func TestAppendixAb(t *testing.T) {
	// BLAKE2b-512("abc") = BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
	//                      4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
	//                      7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
	//                      18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
	out, _ := hex.DecodeString("BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923")
	b2b, err := blake2.NewBlake2b(len(out), nil)
	if err != nil {
		t.Error(err)
		return
	}
	b2b.Update([]byte("abc"))
	h := b2b.Final()
	if !reflect.DeepEqual(h, out) {
		t.Errorf("out  : %x", out)
		t.Errorf("hash : %x", h)
		return
	}
}

type TestVector struct {
	Hash string `json:"hash"`
	Key  string `json:"key"`
	In   string `json:"in"`
	Out  string `json:"out"`
}

func TestVectorsb(t *testing.T) {
	bs, err := ioutil.ReadFile("./blake2b_testvectors.json")
	if err != nil {
		t.Error(err)
		return
	}
	tvs := []TestVector{}
	err = json.Unmarshal(bs, &tvs)
	if err != nil {
		t.Error(err)
		return
	}
	for _, tv := range tvs {
		if tv.Hash != "blake2b" {
			continue
		}
		in, err := hex.DecodeString(tv.In)
		if err != nil {
			t.Error(err)
			return
		}
		key, err := hex.DecodeString(tv.Key)
		if err != nil {
			t.Error(err)
			return
		}
		out, err := hex.DecodeString(tv.Out)
		if err != nil {
			t.Error(err)
			return
		}
		b2b, err := blake2.NewBlake2b(len(out), key)
		if err != nil {
			t.Error(err)
			return
		}
		b2b.Update(in)
		h := b2b.Final()
		if !reflect.DeepEqual(h, out) {
			t.Errorf("in   : %x", in)
			t.Errorf("key  : %x", key)
			t.Errorf("out  : %x", out)
			t.Errorf("hash : %x", h)
			return
		}
	}
}

func Test32b(t *testing.T) {
	out, _ := hex.DecodeString("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
	b2b, err := blake2.NewBlake2b(len(out), nil)
	if err != nil {
		t.Error(err)
		return
	}
	b2b.Update([]byte("abc"))
	h := b2b.Final()
	if !reflect.DeepEqual(h, out) {
		t.Errorf("out  : %x", out)
		t.Errorf("hash : %x", h)
		return
	}
}

func Test48b(t *testing.T) {
	out, _ := hex.DecodeString("6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4")
	b2b, err := blake2.NewBlake2b(len(out), nil)
	if err != nil {
		t.Error(err)
		return
	}
	b2b.Update([]byte("abc"))
	h := b2b.Final()
	if !reflect.DeepEqual(h, out) {
		t.Errorf("out  : %x", out)
		t.Errorf("hash : %x", h)
		return
	}
}
