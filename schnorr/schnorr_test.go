package schnorr_test

import (
	"encoding/csv"
	"encoding/hex"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/tnakagawa/goref/schnorr"
)

func TestVector(t *testing.T) {
	file, err := os.Open("./test-vectors.csv")
	if err != nil {
		t.Errorf("%+v", err)
		return
	}
	defer file.Close()
	r := csv.NewReader(file)
	lines, err := r.ReadAll()
	if err != nil {
		t.Errorf("%+v", err)
		return
	}
	pks := [][]byte{}
	ms := [][]byte{}
	sigs := [][]byte{}
	for idx, line := range lines {
		if idx == 0 {
			continue
		}
		// index
		i, err := strconv.Atoi(line[0])
		if err != nil {
			t.Errorf("line[%d] : %+v", idx, err)
			return
		}
		// secret key
		sec, _ := new(big.Int).SetString(line[1], 16)
		// public key
		pk, err := hex.DecodeString(line[2])
		if err != nil {
			t.Errorf("line[%d] : %+v", idx, err)
			return
		}
		// message
		m, err := hex.DecodeString(line[3])
		if err != nil {
			t.Errorf("line[%d] : %+v", idx, err)
			return
		}
		// signature
		sig, err := hex.DecodeString(line[4])
		if err != nil {
			t.Errorf("line[%d] : %+v", idx, err)
			return
		}
		// verification result
		r := line[5] == "TRUE"
		if err != nil {
			t.Errorf("line[%d] : %+v", idx, err)
			return
		}
		if r {
			pks = append(pks, pk)
			ms = append(ms, m)
			sigs = append(sigs, sig)
		}
		// comment
		c := line[6]
		// t.Logf("%d %x %x %x %x %v %s", i, s, pk, m, sig, r, c)
		err = schnorr.Verify(pk, m, sig)
		// t.Logf("%+v", err)
		if err == nil && r {
			err = schnorr.Verify(pk, m, sig)
			t.Logf("%02d Verify Test Success", i)
		} else if err != nil && !r {
			t.Logf("%02d Verify Test Success / %+v / %+v", i, c, err)
		} else {
			t.Errorf("%02d Verify Test Fail", i)
		}
		if sec != nil {
			s, err := schnorr.Sign(sec, m)
			if err != nil {
				t.Errorf("%02d Sign   Test Fail", i)
			}
			if reflect.DeepEqual(s, sig) {
				t.Logf("%02d Sign   Test Success", i)
			} else {
				t.Errorf("%02d Sign   Test Fail", i)
			}
		}
	}
	err = schnorr.BatchVerify(pks, ms, sigs)
	if err == nil {
		t.Logf("BatchVerify Test Success")
	} else {
		t.Errorf("BatchVerify Test Fail / %+v", err)
	}
}
