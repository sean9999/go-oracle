package delphi

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func someSubKey(t testing.TB) SubKey {
	t.Helper()
	sk := SubKey{}
	sk[5] = byte(5)
	sk[6] = byte(6)
	sk[7] = byte(7)
	sk[8] = byte(8)
	sk[9] = byte(9)
	sk[10] = byte(10)
	sk[11] = byte(11)
	sk[12] = byte(12)
	sk[13] = byte(13)
	sk[14] = byte(14)
	sk[15] = byte(15)
	sk[16] = byte(16)
	sk[17] = byte(17)
	sk[18] = byte(18)
	sk[19] = byte(19)
	sk[20] = byte(20)
	sk[21] = byte(21)
	sk[22] = byte(22)
	sk[23] = byte(23)
	sk[24] = byte(24)
	sk[25] = byte(25)
	sk[26] = byte(26)
	return sk
}

const someKeyString = "000000000005060708090a0b0c0d0e0f101112131415161718191a0000000000"

func TestSubKey_String(t *testing.T) {
	sk := someSubKey(t)
	str := sk.String()
	assert.Equal(t, someKeyString, str)
}

func TestSubkeyFromString(t *testing.T) {

	t.Run("happy path", func(t *testing.T) {
		sk1, err := subkeyFromString(someKeyString)
		assert.NoError(t, err)
		sk2 := someSubKey(t)
		assert.Equal(t, sk1, sk2)
	})

	t.Run("different keys", func(t *testing.T) {
		sk1, err := subkeyFromString("123020000005060708090a0b0c0d0e0f101112131415161718191a0000000456")
		assert.NoError(t, err)
		sk2 := someSubKey(t)
		assert.NotEqual(t, sk1, sk2)
	})

	t.Run("bad hex", func(t *testing.T) {
		sk, err := subkeyFromString("I am most definitely not valid hex.")
		assert.Error(t, err)
		assert.Equal(t, zeroSubKey, sk)
	})

}

func TestNewSubKey(t *testing.T) {
	randy := deterministicReader(t, 5)
	sk1 := newSubKey(randy)
	assert.Equal(t, "0505050505050505050505050505050505050505050505050505050505050505", sk1.String())
}

type generator byte

func (g generator) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(g)
	}
	return len(p), nil
}

func deterministicReader(t testing.TB, seed int) io.Reader {
	t.Helper()
	return generator(seed)
}
