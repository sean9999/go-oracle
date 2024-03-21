package oracle

import "golang.org/x/crypto/chacha20poly1305"

// key is a one-time ephemeral key
// therefore, nonce can (and should) be just a bunch of zeros
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
