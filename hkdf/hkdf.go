package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"
)

// Extract : HKDF-Extract(salt, IKM) -> PRK
func Extract(salt, IKM []byte) []byte {
	// 2.2.  Step 1: Extract
	//    HKDF-Extract(salt, IKM) -> PRK
	//    Options:
	//       Hash     a hash function; HashLen denotes the length of the
	//                hash function output in octets
	//    Inputs:
	//       salt     optional salt value (a non-secret random value);
	//                if not provided, it is set to a string of HashLen zeros.
	//       IKM      input keying material
	//    Output:
	//       PRK      a pseudorandom key (of HashLen octets)
	//    The output PRK is calculated as follows:
	//    PRK = HMAC-Hash(salt, IKM)
	mac := hmac.New(sha256.New, salt)
	mac.Write(IKM)
	PRK := mac.Sum(nil)
	return PRK
}

// Expand : HKDF-Expand(PRK, info, L) -> OKM
func Expand(PRK, info []byte, L int) []byte {
	// 2.3.  Step 2: Expand
	// HKDF-Expand(PRK, info, L) -> OKM
	// Options:
	//   Hash     a hash function; HashLen denotes the length of the
	//            hash function output in octets
	// Inputs:
	//   PRK      a pseudorandom key of at least HashLen octets
	// 	          (usually, the output from the extract step)
	//   info     optional context and application specific information
	// 	          (can be a zero-length string)
	//   L        length of output keying material in octets
	// 	          (<= 255*HashLen)
	if L < 1 || 255*sha256.Size < L {
		return nil
	}
	// Output:
	//   OKM      output keying material (of L octets)
	// The output OKM is calculated as follows:
	//   N = ceil(L/HashLen)
	N := int(math.Ceil(float64(L) / float64(sha256.Size)))
	// 	 T = T(1) | T(2) | T(3) | ... | T(N)
	// 	 where:
	// 	 T(0) = empty string (zero length)
	// 	 T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	// 	 T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	// 	 T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	// 	 ...
	T := []byte{}
	tmp := []byte{}
	for i := 1; i <= N; i++ {
		mac := hmac.New(sha256.New, PRK)
		mac.Write(tmp)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		tmp = mac.Sum(nil)
		T = append(T, tmp...)
	}
	// 	OKM = first L octets of T
	OKM := T[0:L]
	return OKM
}
