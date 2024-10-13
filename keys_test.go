package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

type BunchOfOnes struct{}

func (_ *BunchOfOnes) Read(b []byte) (int, error) {
	for i := range len(b) - 1 {
		b[i] = 17
	}
	return len(b), nil
}

func TestSigningKey(t *testing.T) {
	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, PrivSigningKeySize, len(priv.Bytes()), "length was wrong")
	pub := priv.PublicKey()
	assert.Equal(t, PubSigningKeySize, len(pub.Bytes()), "wrong size")
}

func TestEncryptionKey(t *testing.T) {
	pub, privAndPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, []byte(pub), []byte(privAndPub[32:]), "pub should be the first 32 bytes")
	assert.Equal(t, PrivEncryptKeySize, len(privAndPub), "wrong length")
	assert.Equal(t, PubEncryptKeySize, len(pub), "wrong length")
}

func TestValidate(t *testing.T) {
	km := KeyMatieral{}.Generate(rand.Reader)
	assert.NoError(t, km.validateEncryption(rand.Reader), "sign pairs")
}
