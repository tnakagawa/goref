package btcrev

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// WriteCompactSize ...
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L270
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L287
func WriteCompactSize(w io.Writer, nSize uint64) error {
	if nSize < 253 {
		_, err := w.Write([]byte{byte(nSize)})
		return err
	} else if nSize <= math.MaxUint16 {
		buf := []byte{253, 0, 0}
		binary.LittleEndian.PutUint16(buf[1:], uint16(nSize))
		_, err := w.Write(buf)
		return err
	} else if nSize <= math.MaxUint32 {
		buf := []byte{254, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(buf[1:], uint32(nSize))
		_, err := w.Write(buf)
		return err
	}
	buf := []byte{255, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint64(buf[1:], uint64(nSize))
	_, err := w.Write(buf)
	return err
}

// ReadCompactSize ...
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L270
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L312
func ReadCompactSize(r io.Reader) (uint64, error) {
	buf := make([]byte, 1)
	_, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	chSize := buf[0]
	nSizeRet := uint64(0)
	if chSize < 253 {
		nSizeRet = uint64(chSize)
	} else if chSize == 253 {
		buf := make([]byte, 2)
		_, err := r.Read(buf)
		if err != nil {
			return 0, err
		}
		nSizeRet = uint64(binary.LittleEndian.Uint16(buf))
		if nSizeRet < 253 {
			return 0, errors.New("non-canonical ReadCompactSize()")
		}
	} else if chSize == 254 {
		buf := make([]byte, 4)
		_, err := r.Read(buf)
		if err != nil {
			return 0, err
		}
		nSizeRet = uint64(binary.LittleEndian.Uint32(buf))
		if nSizeRet < 0x10000 {
			return 0, errors.New("non-canonical ReadCompactSize()")
		}
	} else {
		buf := make([]byte, 8)
		_, err := r.Read(buf)
		if err != nil {
			return 0, err
		}
		nSizeRet = binary.LittleEndian.Uint64(buf)
		if nSizeRet < 0x100000000 {
			return 0, errors.New("non-canonical ReadCompactSize()")
		}
	}
	if nSizeRet > 0x02000000 {
		return 0, errors.New("ReadCompactSize(): size too large")
	}
	return nSizeRet, nil
}

// GetSizeOfVarInt ...
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L344
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L389
func GetSizeOfVarInt(n uint64) int {
	nRet := 0
	for {
		nRet++
		if n <= 0x7F {
			break
		}
		n = (n >> 7) - 1
	}
	return nRet
}

// WriteVarInt ...
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L344
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L406
func WriteVarInt(w io.Writer, n uint64) error {
	if n < 0x7f {
		_, err := w.Write([]byte{byte(n)})
		return err
	}
	tmp := []byte{byte(n & 0x7f)}
	for {
		if n <= 0x7f {
			break
		}
		n = (n >> 7) - 1
		tmp = append([]byte{byte((n & 0x7f) | 0x80)}, tmp...)
	}
	_, err := w.Write(tmp)
	return err
}

// ReadVarInt ...
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L344
// https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h#L424
func ReadVarInt(r io.Reader) (uint64, error) {
	n := uint64(0)
	buf := make([]byte, 1)
	for {
		_, err := r.Read(buf)
		if err != nil {
			return 0, err
		}
		chData := buf[0]
		if n > (math.MaxUint64 >> 7) {
			return 0, errors.New("ReadVarInt(): size too large")
		}
		n = (n << 7) | uint64(chData&0x7F)
		if (chData & 0x80) > 0 {
			if n == math.MaxUint64 {
				return 0, errors.New("ReadVarInt(): size too large")
			}
			n++
		} else {
			return n, nil
		}
	}
}

// CScriptCompressor ...
// https://github.com/bitcoin/bitcoin/blob/master/src/compressor.h#L25
type CScriptCompressor struct {
	Script []byte
}

// Serialize ...
// https://github.com/bitcoin/bitcoin/blob/master/src/compressor.h#L25
// https://github.com/bitcoin/bitcoin/blob/master/src/compressor.h#L52
func (c *CScriptCompressor) Serialize(w io.Writer) error {
	return nil
}

// Unserialize ...
// https://github.com/bitcoin/bitcoin/blob/master/src/compressor.h#L25
// https://github.com/bitcoin/bitcoin/blob/master/src/compressor.h#L64
func (c *CScriptCompressor) Unserialize(r io.Reader) error {
	// nSpecialScripts := 6
	// nSize, err := ReadVarInt(r)
	// if err != nil {
	// 	return err
	// }
	// if nSize < nSpecialScripts {
	// 	// c.Script = DecompressScript()
	// }
	return nil
}
