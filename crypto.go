package oracle

import (
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const GLOBAL_SALT = "oracle/v1"

var ErrNoEphemeralKey = errors.New("no ephemeral key")
var UniversalNonce []byte = make([]byte, chacha20poly1305.NonceSize)

// generate an ephemeral X25519 key-pair, and derive a shared secret from it and the recipient's public key
func generateSharedSecret(counterPartyPubKey *ecdh.PublicKey, randomness io.Reader) ([]byte, []byte, error) {

	//	generate an ephemeral private key
	ephemeralPrivKey := make([]byte, curve25519.ScalarSize)
	if _, err := randomness.Read(ephemeralPrivKey); err != nil {
		return nil, nil, err
	}

	//	extract the public key from it
	ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	//	derive a key from the counterparty's public key and ephemeral private key
	secretScalar, err := curve25519.X25519(ephemeralPrivKey, counterPartyPubKey.Bytes())
	if err != nil {
		return nil, nil, err
	}

	//	our salt is the ephemeral public key plus the counterparty's public key
	salt := make([]byte, len(ephemeralPubKey)+len(counterPartyPubKey.Bytes()))
	copy(salt[:len(ephemeralPubKey)], ephemeralPubKey)
	copy(salt[len(ephemeralPubKey):], counterPartyPubKey.Bytes())

	//	derive a symetric key. This is our shared secret
	h := hkdf.New(sha256.New, secretScalar, salt, []byte(GLOBAL_SALT))
	sharedSecret := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecret); err != nil {
		return nil, nil, err
	}

	//	ephemeralPublicKey will be sent over the wire.
	//	sharedSecret will not. That's what we use to encrypt our message
	//	Counterpary will be able to calculate it using their private key and ephemeral public key.
	return sharedSecret, ephemeralPubKey, nil
}

func extractSharedSecret(ephemeralPubKey []byte, recipientPrivKey []byte, recipientPubKey []byte) ([]byte, error) {

	sharedScalar, err := curve25519.X25519(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, len(ephemeralPubKey)+len(recipientPubKey))
	copy(salt[:len(ephemeralPubKey)], ephemeralPubKey)
	copy(salt[len(ephemeralPubKey):], recipientPubKey)

	h := hkdf.New(sha256.New, sharedScalar, salt, []byte(GLOBAL_SALT))
	sharedSecret := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecret); err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, UniversalNonce, plaintext, nil), nil
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, UniversalNonce, ciphertext, nil)
}
