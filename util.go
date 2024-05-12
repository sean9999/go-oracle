package oracle

import (
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrNoEphemeralKey = errors.New("no ephemeral key")
var UniversalNonce []byte = make([]byte, chacha20poly1305.NonceSize)

const GLOBAL_SALT = "oracle/v1"

// key is a one-time ephemeral key
// therefore, nonce can (and should) be just a bunch of zeros (UniversalNonce)
func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, UniversalNonce, plaintext, nil), nil
}

func aeadDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, UniversalNonce, ciphertext, nil)
}

// This is a deterministic [io.Reader] for fake randomness.
type BunchOfZeros struct{}

func (dr *BunchOfZeros) Read(p []byte) (int, error) {
	output := make([]byte, len(p))
	return copy(p, output), nil
}

// Flarg represents all the args and flags after normalization and validation
type Flarg struct {
	Subcommand   string
	ConfigFile   *os.File
	Format       string
	InputStream  io.Reader
	OutputStream io.Writer
}

// The NoFlarg Flarg is used in error conditions
var NoFlarg Flarg
