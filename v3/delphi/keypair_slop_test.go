package delphi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeypair_GenerateDeterministic(t *testing.T) {
	// Use deterministic reader to ensure stable output for coverage on all branches
	r := deterministicReader(t, 1)
	kp := NewKeyPair(r)
	assert.NotNil(t, kp)

	// Public and Private keys should not be zero
	assert.NotEqual(t, ZeroKey, Key(kp.PublicKey()))
	assert.NotEqual(t, ZeroKey, Key(kp.PrivateKey()))

	// Public part should be derivable from private if such behavior is defined
	// At minimum, ensure they are not equal types and have expected lengths
	assert.Equal(t, 64, len(kp.PublicKey().Bytes()))
	assert.Equal(t, 64, len(kp.PrivateKey().Bytes()))

	// Encryption/Signing sub-keys are accessible
	assert.Equal(t, SubKey(kp.PublicKey()[0]), kp.PublicKey().Encryption())
	assert.Equal(t, SubKey(kp.PublicKey()[1]), kp.PublicKey().Signing())
	assert.Equal(t, SubKey(kp.PrivateKey()[0]), kp.PrivateKey().Encryption())
	assert.Equal(t, SubKey(kp.PrivateKey()[1]), kp.PrivateKey().Signing())
}

func TestKeypair_JSON_RoundTrip(t *testing.T) {
	kp1 := NewKeyPair(deterministicReader(t, 2))

	// Marshal entire keypair if it supports JSON, otherwise marshal fields
	type round struct {
		Private Key       `json:"private"`
		Public  PublicKey `json:"public"`
	}
	in := round{Private: Key(kp1.PrivateKey()), Public: kp1.PublicKey()}

	b, err := json.Marshal(in)
	assert.NoError(t, err)

	var out round
	err = json.Unmarshal(b, &out)
	assert.NoError(t, err)

	// Compare round-tripped values
	assert.True(t, Key(kp1.PrivateKey()).Equal(out.Private))
	assert.Equal(t, kp1.PublicKey().String(), out.Public.String())
}

func TestKeypair_NewKeypair_NilReader(t *testing.T) {

	assert.Panics(t, func() {
		NewKeyPair(nil)
	})
	
}

func TestKeypair_PublicPrivateStringAndBytes(t *testing.T) {
	kp := NewKeyPair(deterministicReader(t, 3))
	pubStr := kp.PublicKey().String()
	privStr := Key(kp.PrivateKey()).String()

	assert.Len(t, pubStr, 128)
	assert.Len(t, privStr, 128)

	assert.Len(t, kp.PublicKey().Bytes(), 64)
	assert.Len(t, kp.PrivateKey().Bytes(), 64)
}

func TestKeypair_PublicNickname_DoesNotPanic(t *testing.T) {
	kp := NewKeyPair(deterministicReader(t, 4))
	nick := kp.PublicKey().Nickname()
	assert.NotEmpty(t, nick)
	assert.NotEqual(t, "divine-cloud", nick)
}
