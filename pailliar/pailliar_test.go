package pailliar_test

import (
	"math/big"
	"testing"

	"github.com/tnakagawa/goref/pailliar"
)

func TestPailliar(t *testing.T) {
	pub, pri, err := pailliar.KeyGeneration(2048)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	m1 := pailliar.Rnd(big.NewInt(1000000))
	m2 := pailliar.Rnd(big.NewInt(1000000))
	t.Logf("m1 : %v", m1)
	t.Logf("m2 : %v", m2)
	c1, err := pub.Encryption(m1)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	c2, err := pub.Encryption(m2)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c1 : %v", c1)
	t.Logf("c2 : %v", c2)
	x1, err := pri.Decryption(c1)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	x2, err := pri.Decryption(c2)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("x1 : %v", x1)
	t.Logf("x2 : %v", x2)
	if m1.Cmp(x1) != 0 {
		t.Errorf("m1 != x1 : %v != %v", m1, x1)
		return
	}
	if m2.Cmp(x2) != 0 {
		t.Errorf("m2 != x2 : %v != %v", m2, x2)
		return
	}
	c3 := pub.Mul(c1, c2)
	x3, err := pri.Decryption(c3)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c3 : %v", c3)
	t.Logf("x3 : %v", x3)
	if x3.Cmp(new(big.Int).Add(m1, m2)) != 0 {
		t.Errorf("m1 + m2 != x3 : %v + %v != %v", m1, m2, x3)
		return
	}
	c4 := pub.Exp(c1, m2)
	x4, err := pri.Decryption(c4)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c4 : %v", c4)
	t.Logf("x4 : %v", x4)
	if x4.Cmp(new(big.Int).Mul(m1, m2)) != 0 {
		t.Errorf("m1 * m2 != x4 : %v * %v != %v", m1, m2, x4)
		return
	}
}

func TestGCD(t *testing.T) {
	a := big.NewInt(1071)
	b := big.NewInt(1029)
	c := pailliar.GCD(a, b)
	t.Logf("GCD(%v,%v)=%v", a, b, c)
	if big.NewInt(21).Cmp(c) != 0 {
		t.Errorf("illegal GCD(%v,%v)=%v", a, b, c)
		return
	}
	a = big.NewInt(221)
	b = big.NewInt(153)
	c = pailliar.GCD(a, b)
	t.Logf("GCD(%v,%v)=%v", a, b, c)
	if big.NewInt(17).Cmp(c) != 0 {
		t.Errorf("illegal GCD(%v,%v)=%v", a, b, c)
		return
	}
	a = big.NewInt(144)
	b = big.NewInt(89)
	c = pailliar.GCD(a, b)
	t.Logf("GCD(%v,%v)=%v", a, b, c)
	if big.NewInt(1).Cmp(c) != 0 {
		t.Errorf("illegal GCD(%v,%v)=%v", a, b, c)
		return
	}
}

func TestProbablyPrime(t *testing.T) {
	// http: //homepages.math.uic.edu/~leon/mcs425-s08/handouts/Rabin-Miller-Examples.pdf
	d := map[int64]bool{252601: false, 3057601: false, 104717: true, 577757: true, 101089: true, 280001: true, 95721889: false}
	for k, v := range d {
		r := pailliar.IsProbablyPrime(big.NewInt(k))
		if r != v {
			t.Errorf("error %8d %5v %5v", k, v, r)
			return
		}
		t.Logf("%8d %5v %5v", k, v, r)
	}
}

func TestProbablyPrime2(t *testing.T) {
	d := map[int64]bool{20190523: true, 190523: true, 90523: true, 523: true, 23: true, 3: true}
	for k, v := range d {
		r := pailliar.IsProbablyPrime(big.NewInt(k))
		if r != v {
			t.Errorf("error %8d %5v %5v", k, v, r)
			return
		}
		t.Logf("%8d %5v %5v", k, v, r)
	}
}
