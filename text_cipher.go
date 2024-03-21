package oracle

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// CipherText includes payload and metadata for receiving and decrypting
type CipherText struct {
	Type               string            `json:"type" ion:"type"`
	Headers            map[string]string `json:"headers" ion:"headers"`
	AdditionalData     []byte            `json:"aad" ion:"aad"`
	CipherTextData     []byte            `json:"ciphertext" ion:"ciphertext"`
	Signature          []byte            `json:"signature" ion:"signature"`
	Nonce              []byte            `json:"nonce" ion:"nonce"`
	EphemeralPublicKey []byte            `json:"ephpub" ion:"ephpub"`
	recipient          *ecdh.PrivateKey
	//sender             *ecdh.PublicKey
	sharedSecret []byte
}

func (ct *CipherText) CipherText() []byte {
	return ct.CipherTextData
}

// func (ct *CipherText) UnmarshalText(jsonText []byte) error {
// 	return json.Unmarshal(jsonText, ct)
// }

// func (ct *CipherText) MarshalText() ([]byte, error) {
// 	return json.Marshal(ct)
// }

// func (ct *CipherText) MarshalBinary() ([]byte, error) {
// 	return ion.MarshalBinary(ct)
// }

// func (ct *CipherText) UnmarshalBinary(bits []byte) error {
// 	return ion.Unmarshal(bits, ct)
// }

func (ct *CipherText) UnmarshalPEM(data []byte) error {
	b, rest := pem.Decode(data)

	// eph := make([]byte, 0)
	// hex.Decode(eph, []byte(b.Headers["eph"]))

	keyBytes, err := hex.DecodeString(b.Headers["eph"])
	if err != nil {
		return err
	}

	ct.Type = b.Type
	ct.Headers = b.Headers
	ct.CipherTextData = b.Bytes
	ct.EphemeralPublicKey = keyBytes

	//	@todo: is it appropriate to use "rest" data here
	//	or is this "additional data" in the crypto sense?
	ct.AdditionalData = rest
	return nil
}

func (ct *CipherText) MarshalPEM() ([]byte, error) {

	ct.Headers["eph"] = hex.EncodeToString(ct.EphemeralPublicKey)

	b := &pem.Block{
		Type:    ct.Type,
		Headers: ct.Headers,
		Bytes:   ct.CipherTextData,
	}
	data := pem.EncodeToMemory(b)
	return data, nil
}

// aeadEncrypt encrypts a message with a one-time key.
func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// The nonce is fixed because this function is only used in places where the
	// spec guarantees each key is only used once (by deriving it from values
	// that include fresh randomness), allowing us to save the overhead.
	// For the code that encrypts the actual payload, look at the
	// filippo.io/age/internal/stream package.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

var UniversalNonce []byte = make([]byte, chacha20poly1305.NonceSize)

func aeadDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (ct *CipherText) From(pt *PlainText) {
	ct.Type = pt.Type
	ct.Headers = pt.Headers
	ct.AdditionalData = pt.AdditionalData
	ct.EphemeralPublicKey = pt.EphemeralPublicKey
	ct.Nonce = pt.Nonce
	ct.Signature = pt.Signature
}

func (c1 *CipherText) Clone(c2 *CipherText) {
	c1.Type = c2.Type
	c1.Headers = c2.Headers
	c1.AdditionalData = c2.AdditionalData
	c1.CipherTextData = c2.CipherTextData
	c1.Signature = c2.Signature
	c1.Nonce = c2.Nonce
	c1.EphemeralPublicKey = c2.EphemeralPublicKey
}

func (ct *CipherText) Decrypt() (*PlainText, error) {
	plainTextData, err := aeadDecrypt(ct.sharedSecret, ct.CipherTextData)
	if err != nil {
		return nil, err
	}
	pt := new(PlainText)
	pt.From(ct)
	pt.PlainTextData = plainTextData
	return pt, nil
}

// when receiving
func (ct *CipherText) ExtractSharedSecret() error {
	// @todo: sanity

	sharedSecret, err := curve25519.X25519(ct.recipient.Bytes(), ct.EphemeralPublicKey)
	if err != nil {
		return err
	}

	salt := make([]byte, 0, len(ct.EphemeralPublicKey)+len(ct.recipient.PublicKey().Bytes()))
	salt = append(salt, ct.EphemeralPublicKey...)
	salt = append(salt, ct.recipient.PublicKey().Bytes()...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte("shared-secret"))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return err
	}

	ct.sharedSecret = wrappingKey
	return nil

}

func (ct *CipherText) GenerateSharedSecret(randomness io.Reader) error {
	if len(ct.sharedSecret) > 0 {
		//return errors.New("shared secret seems to already exist")
		return nil
	}
	counterPartyPublicKey := ct.recipient
	ephemeralPrivateKey := make([]byte, curve25519.ScalarSize)
	if _, err := randomness.Read(ephemeralPrivateKey); err != nil {
		return err
	}
	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}
	sharedSecretAsEdwards, err := curve25519.X25519(ephemeralPrivateKey, counterPartyPublicKey.Bytes())
	if err != nil {
		return err
	}
	salt := make([]byte, 0, len(ephemeralPublicKey)+len(counterPartyPublicKey.Bytes()))
	salt = append(salt, ephemeralPublicKey...)
	salt = append(salt, counterPartyPublicKey.Bytes()...)
	h := hkdf.New(sha256.New, sharedSecretAsEdwards, salt, []byte("shared-secret"))
	sharedSecretAsSymetricKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecretAsSymetricKey); err != nil {
		return err
	}
	ct.EphemeralPublicKey = ephemeralPublicKey
	ct.sharedSecret = sharedSecretAsSymetricKey
	//ct.cipher = aead
	return nil
}
