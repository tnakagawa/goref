package btcrev_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/mit-dci/utreexo/utreexo"
)

func TestWriteReadCompactSize(t *testing.T) {
	// BOOST_AUTO_TEST_CASE(compactsize)
	// https://github.com/bitcoin/bitcoin/blob/master/src/test/serialize_tests.cpp#L231
	MAX_SIZE := uint64(0x02000000)
	ss := new(bytes.Buffer)
	var err error
	for i := uint64(1); i < MAX_SIZE; i *= 2 {
		err = utreexo.WriteCompactSize(ss, i-1)
		if err != nil {
			t.Errorf("utreexo.WriteCompactSize error : %+v", err)
			return
		}
		err = utreexo.WriteCompactSize(ss, i)
		if err != nil {
			t.Errorf("utreexo.WriteCompactSize error : %+v", err)
			return
		}
	}
	var j uint64
	for i := uint64(1); i < MAX_SIZE; i *= 2 {
		j, err = utreexo.ReadCompactSize(ss)
		if err != nil {
			t.Errorf("utreexo.ReadCompactSize error : %+v", err)
			return
		}
		if (i - 1) != j {
			t.Errorf("decoded:%d expected:%d", j, i-1)
			return
		}
		j, err = utreexo.ReadCompactSize(ss)
		if err != nil {
			t.Errorf("utreexo.ReadCompactSize error : %+v", err)
			return
		}
		if i != j {
			t.Errorf("decoded:%d expected:%d", j, i)
			return
		}
	}
	// BOOST_AUTO_TEST_CASE(noncanonical)
	// https://github.com/bitcoin/bitcoin/blob/master/src/test/serialize_tests.cpp#L270
	ERROR_MESSAGE := "non-canonical ReadCompactSize()"
	// zero encoded with three bytes:
	ss.Write([]byte{0xfd, 0x00, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
	// 0xfc encoded with three bytes:
	ss.Write([]byte{0xfd, 0xfc, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
	// 0xfd encoded with three bytes is OK:
	ss.Write([]byte{0xfd, 0xfd, 0x00})
	var n uint64
	n, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		t.Errorf("failure %+v", err)
		return
	}
	if n != 0xfd {
		t.Errorf("failure %+x", n)
		return
	}
	// zero encoded with five bytes:
	ss.Write([]byte{0xfe, 0x00, 0x00, 0x00, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
	// 0xffff encoded with five bytes:
	ss.Write([]byte{0xfe, 0xff, 0xff, 0x00, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
	// zero encoded with nine bytes:
	ss.Write([]byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
	// 0x01ffffff encoded with nine bytes:
	ss.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00})
	_, err = utreexo.ReadCompactSize(ss)
	if err != nil {
		if err.Error() != ERROR_MESSAGE {
			t.Errorf("failure")
			return
		}
	} else {
		t.Error("no error")
		return
	}
}

func TestWriteReadVarInt(t *testing.T) {
	// BOOST_AUTO_TEST_CASE(varints)
	// https://github.com/bitcoin/bitcoin/blob/master/src/test/serialize_tests.cpp#L178
	// encode
	ss := new(bytes.Buffer)
	var err error
	size := 0
	for i := uint64(0); i < 100000; i++ {
		err = utreexo.WriteVarInt(ss, i)
		if err != nil {
			t.Errorf("failure %+v", err)
			return
		}
		size += utreexo.GetSizeOfVarInt(i)
		if size != len(ss.Bytes()) {
			t.Errorf("failure")
			return
		}
	}
	for i := uint64(0); i < 100000000000; i += 999999937 {
		err = utreexo.WriteVarInt(ss, i)
		if err != nil {
			t.Errorf("failure %+v", err)
			return
		}
		size += utreexo.GetSizeOfVarInt(i)
		if size != len(ss.Bytes()) {
			t.Errorf("failure")
			return
		}
	}
	// decode
	for i := uint64(0); i < 100000; i++ {
		j, err := utreexo.ReadVarInt(ss)
		if err != nil {
			t.Errorf("failure %+v", err)
			return
		}
		if i != j {
			t.Errorf("decoded:%d expected:%d", j, i)
			return
		}
	}
	for i := uint64(0); i < 100000000000; i += 999999937 {
		j, err := utreexo.ReadVarInt(ss)
		if err != nil {
			t.Errorf("failure %+v", err)
			return
		}
		if i != j {
			t.Errorf("decoded:%d expected:%d", j, i)
			return
		}
	}
	// BOOST_AUTO_TEST_CASE(varints_bitpatterns)
	// https://github.com/bitcoin/bitcoin/blob/master/src/test/serialize_tests.cpp#L210
	nums := []uint64{0, 0x7f, 0x80, 0x1234, 0xffff, 0x123456, 0x80123456, 0xffffffff,
		0x7fffffffffffffff, 0xffffffffffffffff}
	data := [][]byte{
		[]byte{0x00}, []byte{0x7f}, []byte{0x80, 0x00}, []byte{0xa3, 0x34},
		[]byte{0x82, 0xfe, 0x7f}, []byte{0xc7, 0xe7, 0x56}, []byte{0x86, 0xff, 0xc7, 0xe7, 0x56},
		[]byte{0x8e, 0xfe, 0xfe, 0xfe, 0x7f}, []byte{0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0x7f},
		[]byte{0x80, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0x7f},
	}
	ss.Reset()
	for i, _ := range nums {
		err := utreexo.WriteVarInt(ss, nums[i])
		if err != nil {
			t.Errorf("failure %+v", err)
			return
		}
		if !reflect.DeepEqual(data[i], ss.Bytes()) {
			t.Errorf("failure")
			return
		}
		ss.Reset()
	}
}
