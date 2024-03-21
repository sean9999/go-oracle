package oracle

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"

	"github.com/amazon-ion/ion-go/ion"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var UniversalNonce []byte = make([]byte, chacha20poly1305.NonceSize)

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

func (ct *CipherText) UnmarshalPEM(data []byte) error {
	b, rest := pem.Decode(data)
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

func (ct *CipherText) MarshalIon() ([]byte, error) {
	return ion.MarshalBinary(ct)
}

func (ct *CipherText) UnmarshalIon(bin []byte) error {
	return ion.Unmarshal(bin, ct)
}

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
