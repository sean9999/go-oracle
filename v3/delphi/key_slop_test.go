package delphi

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests focus on branches and methods that are not fully covered by key_test.go,
// aiming to push coverage to 100% for key.go while keeping key_test.go unchanged.

func TestPublicKey_StringAndJSON(t *testing.T) {
	k := NewKey(deterministicReader(t, 4))
	pub := PublicKey(k)

	// String should match Key(k).String()
	assert.Equal(t, Key(k).String(), pub.String())

	// MarshalJSON should marshal hex-encoded string
	j, err := pub.MarshalJSON()
	assert.NoError(t, err)

	// UnmarshalJSON should reconstruct the same public key
	var round PublicKey
	err = round.UnmarshalJSON(j)
	assert.NoError(t, err)
	assert.Equal(t, pub.String(), round.String())
}

func TestPublicKey_UnmarshalJSON_Errors(t *testing.T) {
	var pk PublicKey

	// invalid JSON (not a string)
	err := pk.UnmarshalJSON([]byte(`123`))
	assert.Error(t, err)

	// invalid hex string
	err = pk.UnmarshalJSON([]byte(`i am bad hex.`))
	assert.Error(t, err)

	// too short after decode for Write
	// subKeySize*2 is 64, so 2 hex chars -> 1 byte, definitely too short
	err = pk.UnmarshalJSON([]byte(`"aa"`))
	assert.Error(t, err)
}

func TestKey_JSON_Unmarshal_Errors(t *testing.T) {
	var k Key

	// invalid JSON (not a string)
	err := k.UnmarshalJSON([]byte(`{"not":"a string"}`))
	assert.Error(t, err)

	// invalid hex in string
	err = k.UnmarshalJSON([]byte(`"not-hex"`))

	assert.Error(t, err)

	// too short for Write
	err = k.UnmarshalJSON([]byte(`"aa"`))
	assert.Error(t, err)
}

func TestKeyFromString_SuccessAndErrors(t *testing.T) {
	// success path
	orig := NewKey(deterministicReader(t, 6))
	s := orig.String()
	got, err := KeyFromString(s)
	assert.NoError(t, err)
	assert.True(t, got.Equal(orig))

	// invalid hex
	_, err = KeyFromString("not-hex")
	assert.Error(t, err)

	// wrong size (too short)
	_, err = KeyFromString("aa")
	assert.Error(t, err)
}

func TestKey_Read_WrongSizeErrorWrapping(t *testing.T) {
	k := NewKey(deterministicReader(t, 2))
	buf := make([]byte, 10) // too small
	_, err := k.Read(buf)
	assert.Error(t, err)
	// should wrap ErrWrongSize
	assert.ErrorIs(t, err, ErrWrongSize)
}

func TestKeyFromBytes_ZeroKeyError(t *testing.T) {
	// exactly correct size but all zeroes -> ErrZeroKey
	data := make([]byte, subKeySize*2)
	k, err := KeyFromBytes(data)
	assert.ErrorIs(t, err, ErrZeroKey)
	assert.True(t, k.Equal(ZeroKey))
}

func TestKeyToInt64AndNickname(t *testing.T) {
	// Implicitly cover toInt64 via Nickname since toInt64 is unexported
	// Ensure it doesn't panic for a non-zero key and returns a deterministic name
	k := PublicKey(NewKey(deterministicReader(t, 8)))
	name := k.Nickname()
	assert.NotEmpty(t, name)
	assert.NotEqual(t, "divine-cloud", name)
}

func TestKey_Write_TooShort(t *testing.T) {
	var k Key
	// provide fewer than required bytes
	n, err := k.Write(make([]byte, subKeySize*2-1))
	assert.Zero(t, n)
	assert.Error(t, err)
}

func TestKey_Read_ZeroKeyPanics(t *testing.T) {
	var k Key // zero key
	buf := make([]byte, subKeySize*2)
	assert.Panics(t, func() {
		_, _ = k.Read(buf)
	})
}

func TestNewKey_NoReaderIsZero(t *testing.T) {
	k := NewKey(nil)
	assert.True(t, k.Equal(ZeroKey))
}

func TestKey_Read_HappyPathCopiesAndEOF(t *testing.T) {
	k := NewKey(deterministicReader(t, 9))
	buf := make([]byte, subKeySize*2)
	n, err := k.Read(buf)
	assert.Equal(t, subKeySize*2, n)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, k.Bytes(), buf[:subKeySize*2])
}

func TestKey_Equal_SelfAndDifferent(t *testing.T) {
	k1 := NewKey(deterministicReader(t, 10))
	k2 := NewKey(deterministicReader(t, 11))
	assert.True(t, k1.Equal(k1))
	assert.False(t, k1.Equal(k2))
}

func TestPublicKey_Write_SizeChecksAndCopy(t *testing.T) {
	var pk PublicKey

	// too short
	n, err := pk.Write(make([]byte, subKeySize*2-1))
	assert.Zero(t, n)
	assert.Error(t, err)

	// exact size
	data := make([]byte, subKeySize*2)
	for i := range data {
		data[i] = byte(i)
	}
	n, err = pk.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, subKeySize*2, n)
	assert.Equal(t, data, PublicKey(pk).Bytes())
}

func TestKey_MarshalUnmarshalJSON_RoundTrip(t *testing.T) {
	k := NewKey(deterministicReader(t, 12))
	b, err := k.MarshalJSON()
	assert.NoError(t, err)

	var out Key
	err = out.UnmarshalJSON(b)
	assert.NoError(t, err)
	assert.True(t, k.Equal(out))

	// Also validate it's valid JSON string of hex
	var s string
	err = json.Unmarshal(b, &s)
	assert.NoError(t, err)
	_, err = hex.DecodeString(s)
	assert.NoError(t, err)
}

func TestErrorTypesPresence(t *testing.T) {
	// Make sure error vars exist and are comparable
	assert.EqualError(t, ErrWrongSize, "wrong size")
	assert.EqualError(t, ErrZeroKey, "zero key")
}
