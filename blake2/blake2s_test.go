package blake2_test

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/tnakagawa/goref/blake2"
)

func TestAppendixAs(t *testing.T) {
	// BLAKE2s-256("abc") = 50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F
	//                      37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82
	out, _ := hex.DecodeString("508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982")
	b2s, err := blake2.NewBlake2s(len(out), nil)
	if err != nil {
		t.Error(err)
		return
	}
	b2s.Update([]byte("abc"))
	h := b2s.Final()
	if !reflect.DeepEqual(h, out) {
		t.Errorf("out  : %x", out)
		t.Errorf("hash : %x", h)
		return
	}
}

func TestVectorss(t *testing.T) {
	bs, err := ioutil.ReadFile("./blake2s_testvectors.json")
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
		if tv.Hash != "blake2s" {
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
		b2s, err := blake2.NewBlake2s(len(out), key)
		if err != nil {
			t.Error(err)
			return
		}
		b2s.Update(in)
		h := b2s.Final()
		if !reflect.DeepEqual(h, out) {
			t.Errorf("in   : %x", in)
			t.Errorf("key  : %x", key)
			t.Errorf("out  : %x", out)
			t.Errorf("hash : %x", h)
			return
		}
	}
}
