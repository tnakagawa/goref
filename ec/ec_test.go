package ec_test

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/tnakagawa/goref/ec"
)

type Secp256k1Test struct {
	Title   string              `json:"title"`
	Curve   string              `json:"curve"`
	URL     string              `json:"url"`
	Vectors []map[string]string `json:"vectors"`
}

func TestVector(t *testing.T) {
	bs, err := ioutil.ReadFile("./secp256k1test.json")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var test Secp256k1Test
	err = json.Unmarshal(bs, &test)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	cnt := 0
	for _, vector := range test.Vectors {
		k, ok := new(big.Int).SetString(vector["k"], 10)
		if !ok {
			t.Errorf("error SetString %v", vector["k"])
			return
		}
		x, ok := new(big.Int).SetString(vector["x"], 16)
		if !ok {
			t.Errorf("error SetString %v", vector["x"])
			return
		}
		y, ok := new(big.Int).SetString(vector["y"], 16)
		if !ok {
			t.Errorf("error SetString %v", vector["y"])
			return
		}
		P := ec.Mul(k, ec.G)
		if x.Cmp(P.X) != 0 || y.Cmp(P.Y) != 0 {
			t.Errorf("not match %v", k)
			t.Logf("%x,%x", x.Bytes(), y.Bytes())
			t.Logf("%x,%x", P.X.Bytes(), P.Y.Bytes())
			return
		}
		cnt++
	}
	t.Log(cnt)
}
