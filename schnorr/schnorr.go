package schnorr

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/tnakagawa/goref/ec"
	"github.com/tnakagawa/goref/sha256"
)

// The constant p refers to the field size, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F.
var p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// The constant n refers to the curve order, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.
var n, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func p2bs(p *ec.Point) []byte {
	bs := make([]byte, 1)
	bs[0] = byte(0x02 + p.Y.Bit(0))
	return append(bs, bytes(p.X)...)
}

// The function bytes(x), where x is an integer, returns the 32-byte encoding of x, most significant byte first.
func bytes(x *big.Int) []byte {
	bs := make([]byte, 32)
	l := len(x.Bytes())
	if l > len(bs) {
		copy(bs, x.Bytes()[:32])
	} else {
		copy(bs[32-l:], x.Bytes())
	}
	return bs
}

// The function lift_x(x), where x is an integer in range 0..p-1,
// returns the point P for which x(P) = x and y(P) is a quadratic residue modulo p,
// or fails if no such point exists.
// The function lift_x(x) is equivalent to the following pseudocode:
func liftX(x *big.Int) (*ec.Point, error) {
	// Let c = x^3 + 7 mod p.
	c := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), p), big.NewInt(7)), p)
	// Let y = c^{(p+1)/4} mod p.
	y := new(big.Int).Exp(c, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(1)), big.NewInt(4)), p)
	// Fail if c ≠ y^2 mod p.
	if c.Cmp(new(big.Int).Exp(y, big.NewInt(2), p)) != 0 {
		return nil, fmt.Errorf("c ≠ y^2 mod p")
	}
	// Return the unique point P such that x(P) = x and y(P) = y.
	P := &ec.Point{X: x, Y: y}
	return P, nil
}

// The function point(x), where x is a 32-byte array, returns the point P = lift_x(int(x)).
func point(x []byte) (*ec.Point, error) {
	if len(x) != 32 {
		return nil, fmt.Errorf("illigal x size")
	}
	P, err := liftX(new(big.Int).SetBytes(x))
	if err != nil {
		return nil, err
	}
	return P, nil
}

// The function hash(x), where x is a byte array, returns the 32-byte SHA256 hash of x.
func hash(x []byte) []byte {
	return sha256.Digest(x)
}

// The function jacobi(x), where x is an integer, returns the Jacobi symbol of x / p.
// It is equal to x^{(p-1)/2} mod p (Euler's criterion).
func jacobi(x *big.Int) *big.Int {
	return new(big.Int).Exp(x, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2)), p)
}

// Verify : The signature is valid if and only if the algorithm below does not fail.
// The public key pk: a 32-byte array
// The message m: a 32-byte array
// A signature sig: a 64-byte array
func Verify(pk, m, sig []byte) error {
	if len(pk) != 32 {
		return fmt.Errorf("illegal public key size")
	}
	if len(m) != 32 {
		return fmt.Errorf("illegal message size")
	}
	if len(sig) != 64 {
		return fmt.Errorf("illegal signature size")
	}
	// Let P = point(pk); fail if point(pk) fails.
	P, err := point(pk)
	if err != nil {
		return err
	}
	// Let r = int(sig[0:32]); fail if r ≥ p.
	r := new(big.Int).SetBytes(sig[0:32])
	if r.Cmp(p) >= 0 {
		return fmt.Errorf("r ≥ p")
	}
	// Let s = int(sig[32:64]); fail if s ≥ n.
	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(n) >= 0 {
		return fmt.Errorf("s ≥ n")
	}
	// Let e = int(hash(bytes(r) || bytes(P) || m)) mod n
	e := new(big.Int).SetBytes(hash(append(append(bytes(r), bytes(P.X)...), m...)))
	// Let R = sG - eP.
	R := ec.Add(ec.Mul(s, ec.G), ec.Mul(new(big.Int).Mod(new(big.Int).Neg(e), n), P))
	// Fail if infinite(R).
	if R.Infinite() {
		return fmt.Errorf("infinite(R)")
	}
	// Fail if jacobi(y(R)) ≠ 1 or x(R) ≠ r.
	if jacobi(R.Y).Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("jacobi(y(R)) ≠ 1")
	}
	if R.X.Cmp(r) != 0 {
		return fmt.Errorf("x(R) ≠ r")
	}
	return nil
}

// BatchVerify : All provided signatures are valid with overwhelming probability if and only if the algorithm below does not fail.
// The number u of signatures
// The public keys pk1..u: u 32-byte arrays
// The messages m1..u: u 32-byte arrays
// The signatures sig1..u: u 64-byte arrays
func BatchVerify(pk, m, sig [][]byte) error {
	u := len(pk)
	if u != len(m) || u != len(sig) {
		return fmt.Errorf("illieal parameters size")
	}
	// Generate u-1 random integers a2...u in the range 1...n-1.
	// They are generated deterministically using a CSPRNG seeded by a cryptographic hash of all inputs of the algorithm, i.e. seed = seed_hash(pk1..pku || m1..mu || sig1..sigu ).
	// A safe choice is to instantiate seed_hash with SHA256 and use ChaCha20 with key seed as a CSPRNG to generate 256-bit integers, skipping integers not in the range 1...n-1.
	as := []*big.Int{}
	for i := 1; i < u; i++ {
		a, err := rand.Int(rand.Reader, n)
		if err != nil {
			return err
		}
		as = append(as, a)
	}
	Ps := []*ec.Point{}
	ss := []*big.Int{}
	es := []*big.Int{}
	Rs := []*ec.Point{}
	// For i = 1 .. u:
	for i := 0; i < u; i++ {
		// Let Pi = point(pki); fail if point(pki) fails.
		P, err := point(pk[i])
		if err != nil {
			return err
		}
		Ps = append(Ps, P)
		// Let r = int(sigi[0:32]); fail if r ≥ p.
		r := new(big.Int).SetBytes(sig[i][0:32])
		if r.Cmp(p) >= 0 {
			return fmt.Errorf("r ≥ p")
		}
		// Let si = int(sigi[32:64]); fail if si ≥ n.
		s := new(big.Int).SetBytes(sig[i][32:64])
		if s.Cmp(n) >= 0 {
			return fmt.Errorf("si ≥ n")
		}
		ss = append(ss, s)
		// Let ei = int(hash(bytes(r) || bytes(Pi) || mi)) mod n.
		e := new(big.Int).SetBytes(hash(append(append(bytes(r), bytes(P.X)...), m[i]...)))
		es = append(es, e)
		// Let Ri = lift_x(r); fail if lift_x(r) fails.
		R, err := liftX(r)
		if err != nil {
			return err
		}
		Rs = append(Rs, R)
	}
	// Fail if (s1 + a2s2 + ... + ausu)G ≠ R1 + a2R2 + ... + auRu + e1P1 + (a2e2)P2 + ... + (aueu)Pu.
	left := ec.Mul(ss[0], ec.G)
	right := ec.Add(Rs[0], ec.Mul(es[0], Ps[0]))
	for i := 1; i < u; i++ {
		left = ec.Add(left, ec.Mul(new(big.Int).Mul(as[i-1], ss[i]), ec.G))
		right = ec.Add(right, ec.Add(ec.Mul(as[i-1], Rs[i]), ec.Mul(new(big.Int).Mul(as[i-1], es[i]), Ps[i])))
	}
	if left.X.Cmp(right.X) != 0 || left.Y.Cmp(right.Y) != 0 {
		return fmt.Errorf("(s1 + a2s2 + ... + ausu)G ≠ R1 + a2R2 + ... + auRu + e1P1 + (a2e2)P2 + ... + (aueu)Pu")
	}
	return nil
}

// Sign is Signing.
// The secret key d' : an integer in the range 1..n-1
// The message m: a 32-byte array
func Sign(dd *big.Int, m []byte) ([]byte, error) {
	// To sign m for public key bytes(dG):
	// Let P = d'G
	P := ec.Mul(dd, ec.G)
	// Let d = d' if jacobi(y(P)) = 1, otherwise let d = n - d' .
	d := new(big.Int).Set(dd)
	if jacobi(P.Y).Cmp(big.NewInt(1)) != 0 {
		d = new(big.Int).Sub(n, dd)
	}
	// Let k' = int(hash(bytes(d) || m)) mod n.
	kd := new(big.Int).Mod(new(big.Int).SetBytes(hash(append(bytes(d), m...))), n)
	// Fail if k' = 0.
	if kd.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("k' = 0")
	}
	// Let R = k'G.
	R := ec.Mul(kd, ec.G)
	// Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k' .
	k := new(big.Int).Set(kd)
	if jacobi(R.Y).Cmp(big.NewInt(1)) != 0 {
		k = new(big.Int).Sub(n, kd)
	}
	// Let e = int(hash(bytes(R) || bytes(P) || m)) mod n.
	e := new(big.Int).Mod(new(big.Int).SetBytes(hash(append(append(bytes(R.X), bytes(P.X)...), m...))), n)
	// The signature is bytes(R) || bytes((k + ed) mod n).
	sig := append(bytes(R.X), bytes(new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(e, d)), n))...)
	return sig, nil
}
