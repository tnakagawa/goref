package chacha20poly1305

// https://tools.ietf.org/html/rfc8439

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// Qround :
func Qround(state []uint32, p1, p2, p3, p4 int) error {
	if len(state) != 16 {
		return fmt.Errorf("state size error : %d", len(state))
	}
	if p1 < 0 || 15 < p1 || p2 < 0 || 15 < p2 || p3 < 0 || 15 < p3 || p4 < 0 || 15 < p4 {
		return fmt.Errorf("illegal position : %d %d %d %d", p1, p2, p3, p4)
	}
	a := state[p1]
	b := state[p2]
	c := state[p3]
	d := state[p4]
	tmp := uint32(0)
	// 1.  a += b; d ^= a; d <<<= 16;
	a += b
	d ^= a
	tmp = d >> (32 - 16)
	d = d<<16 + tmp
	// 2.  c += d; b ^= c; b <<<= 12;
	c += d
	b ^= c
	tmp = b >> (32 - 12)
	b = b<<12 + tmp
	// 3.  a += b; d ^= a; d <<<= 8;
	a += b
	d ^= a
	tmp = d >> (32 - 8)
	d = d<<8 + tmp
	// 4.  c += d; b ^= c; b <<<= 7;
	c += d
	b ^= c
	tmp = b >> (32 - 7)
	b = b<<7 + tmp
	state[p1] = a
	state[p2] = b
	state[p3] = c
	state[p4] = d
	return nil
}

// InnerBlock :
func InnerBlock(state []uint32) error {
	// inner_block (state):
	// Qround(state, 0, 4, 8, 12)
	// Qround(state, 1, 5, 9, 13)
	// Qround(state, 2, 6, 10, 14)
	// Qround(state, 3, 7, 11, 15)
	// Qround(state, 0, 5, 10, 15)
	// Qround(state, 1, 6, 11, 12)
	// Qround(state, 2, 7, 8, 13)
	// Qround(state, 3, 4, 9, 14)
	// end
	err := Qround(state, 0, 4, 8, 12)
	if err != nil {
		return err
	}
	err = Qround(state, 1, 5, 9, 13)
	if err != nil {
		return err
	}
	err = Qround(state, 2, 6, 10, 14)
	if err != nil {
		return err
	}
	err = Qround(state, 3, 7, 11, 15)
	if err != nil {
		return err
	}
	err = Qround(state, 0, 5, 10, 15)
	if err != nil {
		return err
	}
	err = Qround(state, 1, 6, 11, 12)
	if err != nil {
		return err
	}
	err = Qround(state, 2, 7, 8, 13)
	if err != nil {
		return err
	}
	err = Qround(state, 3, 4, 9, 14)
	if err != nil {
		return err
	}
	return nil
}

// ChaCha20Block :
func ChaCha20Block(key []byte, counter uint32, nonce []byte) ([]byte, error) {
	// chacha20_block(key, counter, nonce):
	// state = constants | key | counter | nonce
	state := make([]uint32, 16)
	state[0] = uint32(0x61707865)
	state[1] = uint32(0x3320646e)
	state[2] = uint32(0x79622d32)
	state[3] = uint32(0x6b206574)
	if len(key) != 32 {
		return nil, fmt.Errorf("key size error : %d", len(key))
	}
	for i := 0; i < 8; i++ {
		state[i+4] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}
	state[12] = counter
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce size error : %d", len(nonce))
	}
	for i := 0; i < 3; i++ {
		state[i+13] = binary.LittleEndian.Uint32(nonce[i*4 : i*4+4])
	}
	// initial_state = state
	initialState := make([]uint32, 16)
	copy(initialState, state)
	// for i=1 upto 10
	//    inner_block(state)
	//    end
	for i := 0; i < 10; i++ {
		err := InnerBlock(state)
		if err != nil {
			return nil, err
		}
	}
	// state += initial_state
	for i := range state {
		state[i] = state[i] + initialState[i]
	}
	// return serialize(state)
	bs := make([]byte, 64)
	for i, v := range state {
		binary.LittleEndian.PutUint32(bs[i*4:], v)
	}
	return bs, nil
	// end
}

// ChaCha20Encrypt :
func ChaCha20Encrypt(key []byte, counter uint32, nonce []byte, plaintext []byte) ([]byte, error) {
	// chacha20_encrypt(key, counter, nonce, plaintext):
	encryptedMessage := []byte{}
	// for j = 0 upto floor(len(plaintext)/64)-1
	size := int(math.Floor(float64(len(plaintext)) / float64(64)))
	for j := 0; j < size; j++ {
		//    key_stream = chacha20_block(key, counter+j, nonce)
		keyStream, err := ChaCha20Block(key, counter+uint32(j), nonce)
		if err != nil {
			return nil, err
		}
		//    block = plaintext[(j*64)..(j*64+63)]
		block := plaintext[j*64 : (j+1)*64]
		//    encrypted_message +=  block ^ key_stream
		for i := range block {
			encryptedMessage = append(encryptedMessage, block[i]^keyStream[i])
		}
		//    end
	}
	// if ((len(plaintext) % 64) != 0)
	if len(plaintext)%64 != 0 {
		//    j = floor(len(plaintext)/64)
		j := int(math.Floor(float64(len(plaintext)) / float64(64)))
		//    key_stream = chacha20_block(key, counter+j, nonce)
		keyStream, err := ChaCha20Block(key, counter+uint32(j), nonce)
		if err != nil {
			return nil, err
		}
		//    block = plaintext[(j*64)..len(plaintext)-1]
		block := plaintext[j*64 : len(plaintext)]
		//    encrypted_message += (block^key_stream)[0..len(plaintext)%64]
		for i := range block {
			encryptedMessage = append(encryptedMessage, block[i]^keyStream[i])
		}
		//    end
	}
	// return encrypted_message
	return encryptedMessage, nil
	// end
}

// Poly1305Mac :
func Poly1305Mac(msg []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key size error : %d", len(key))
	}
	// clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
	CLAMP, _ := new(big.Int).SetString("0ffffffc0ffffffc0ffffffc0fffffff", 16)
	// poly1305_mac(msg, key):
	//   r = le_bytes_to_num(key[0..15])
	tmp := make([]byte, 16)
	for i := range tmp {
		tmp[i] = key[15-i]
	}
	r := new(big.Int).SetBytes(tmp)
	//   clamp(r)
	r = new(big.Int).And(r, CLAMP)
	//   s = le_bytes_to_num(key[16..31])
	for i := range tmp {
		tmp[i] = key[31-i]
	}
	s := new(big.Int).SetBytes(tmp)
	//   a = 0  /* a is the accumulator */
	a := big.NewInt(0)
	//   p = (1<<130)-5
	p := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(130), nil), big.NewInt(5))
	//   for i=1 upto ceil(msg length in bytes / 16)
	size := int(math.Ceil(float64(len(msg)) / float64(16)))
	for i := 1; i <= size; i++ {
		//      n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
		var tmp []byte
		if len(msg) >= i*16 {
			tmp = make([]byte, 17)
			tmp[0] = byte(0x01)
			for j := range tmp {
				if j == 0 {
					continue
				}
				tmp[j] = msg[i*16-j]
			}
		} else {
			tmp = make([]byte, len(msg)-(i-1)*16+1)
			tmp[0] = byte(0x01)
			for j := range tmp {
				if j == 0 {
					continue
				}
				tmp[j] = msg[len(msg)-j]
			}
		}
		n := new(big.Int).SetBytes(tmp)
		//      a += n
		a = new(big.Int).Add(a, n)
		//      a = (r * a) % p
		a = new(big.Int).Mod(new(big.Int).Mul(r, a), p)
		//      end
	}
	//   a += s
	a = new(big.Int).Add(a, s)
	//   return num_to_16_le_bytes(a)
	tag := make([]byte, 16)
	bs := a.Bytes()
	for i := range bs {
		if i > 15 {
			break
		}
		tag[i] = bs[len(bs)-i-1]
	}
	return tag, nil
	//   end
}

// Poly1305KeyGen :
func Poly1305KeyGen(key, nonce []byte) ([]byte, error) {
	// poly1305_key_gen(key,nonce):
	// counter = 0
	counter := uint32(0)
	// block = chacha20_block(key,counter,nonce)
	block, err := ChaCha20Block(key, counter, nonce)
	if err != nil {
		return nil, err
	}
	// return block[0..31]
	return block[0:32], nil
	// end
}

// Pad16 :
func Pad16(x []byte) []byte {
	// pad16(x):
	// if (len(x) % 16)==0
	if (len(x) % 16) == 0 {
		//    then return NULL
		return []byte{}
	}
	//    else return copies(0, 16-(len(x)%16))
	bs := make([]byte, 16-(len(x)%16))
	return bs
	// end
}

// ChaCha20AeadEncrypt :
func ChaCha20AeadEncrypt(aad, key, iv, constant, plaintext []byte) ([]byte, []byte, error) {
	// chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
	// nonce = constant | iv
	nonce := []byte{}
	nonce = append(nonce, constant...)
	nonce = append(nonce, iv...)
	// otk = poly1305_key_gen(key, nonce)
	otk, err := Poly1305KeyGen(key, nonce)
	if err != nil {
		return nil, nil, err
	}
	// ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
	ciphertext, err := ChaCha20Encrypt(key, uint32(1), nonce, plaintext)
	if err != nil {
		return nil, nil, err
	}
	// mac_data = aad | pad16(aad)
	macData := []byte{}
	macData = append(macData, aad...)
	macData = append(macData, Pad16(aad)...)
	// mac_data |= ciphertext | pad16(ciphertext)
	macData = append(macData, ciphertext...)
	macData = append(macData, Pad16(ciphertext)...)
	// mac_data |= num_to_8_le_bytes(aad.length)
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, uint64(len(aad)))
	macData = append(macData, tmp...)
	// mac_data |= num_to_8_le_bytes(ciphertext.length)
	binary.LittleEndian.PutUint64(tmp, uint64(len(ciphertext)))
	macData = append(macData, tmp...)
	// tag = poly1305_mac(mac_data, otk)
	tag, err := Poly1305Mac(macData, otk)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, tag, nil
	// return (ciphertext, tag)
}

// ChaCha20AeadDecrypt :
func ChaCha20AeadDecrypt(aad, key, iv, constant, ciphertext []byte) ([]byte, []byte, error) {
	// chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
	// nonce = constant | iv
	nonce := []byte{}
	nonce = append(nonce, constant...)
	nonce = append(nonce, iv...)
	// otk = poly1305_key_gen(key, nonce)
	otk, err := Poly1305KeyGen(key, nonce)
	if err != nil {
		return nil, nil, err
	}
	// plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)
	plaintext, err := ChaCha20Encrypt(key, uint32(1), nonce, ciphertext)
	if err != nil {
		return nil, nil, err
	}
	// mac_data = aad | pad16(aad)
	macData := []byte{}
	macData = append(macData, aad...)
	macData = append(macData, Pad16(aad)...)
	// mac_data |= ciphertext | pad16(ciphertext)
	macData = append(macData, ciphertext...)
	macData = append(macData, Pad16(ciphertext)...)
	// mac_data |= num_to_8_le_bytes(aad.length)
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, uint64(len(aad)))
	macData = append(macData, tmp...)
	// mac_data |= num_to_8_le_bytes(ciphertext.length)
	binary.LittleEndian.PutUint64(tmp, uint64(len(ciphertext)))
	macData = append(macData, tmp...)
	// tag = poly1305_mac(mac_data, otk)
	tag, err := Poly1305Mac(macData, otk)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, tag, nil
	// return (ciphertext, tag)
}
