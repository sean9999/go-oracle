package oracle

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/pem"
	"io"

	"github.com/sean9999/go-oracle/essence"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const GLOBAL_SALT = "oracle/v1"

// PlainText includes payload and metadata for encrypting and sending
type PlainText struct {
	Type               string            `json:"type" ion:"type"`
	Headers            map[string]string `json:"headers" ion:"headers"`
	AdditionalData     []byte            `json:"aad" ion:"aad"`
	PlainTextData      []byte            `json:"plaintext" ion:"plaintext"`
	Signature          []byte            `json:"signature" ion:"signature"`
	Nonce              []byte            `json:"nonce" ion:"nonce"`
	EphemeralPublicKey []byte            `json:"ephpub" ion:"ephpub"`
	recipient          *ecdh.PublicKey
	//sender             *ecdh.PrivateKey
	sharedSecret []byte
}

func ComposeLetter(recipient *ecdh.PublicKey, subject string, body []byte) *PlainText {
	hdrs := map[string]string{
		"subject": subject,
	}
	pt := PlainText{
		Headers:       hdrs,
		Type:          "ORACLE MESSAGE",
		PlainTextData: body,
		recipient:     recipient,
	}
	return &pt
}

// func (pt *PlainText) UnmarshalText(jsonText []byte) error {
// 	return json.Unmarshal(jsonText, pt)
// }

// func (pt *PlainText) MarshalText() ([]byte, error) {
// 	return json.Marshal(pt)
// }

func (pt *PlainText) String() string {
	return string(pt.PlainTextData)
}

// func (pt *PlainText) MarshalBinary() ([]byte, error) {
// 	return ion.MarshalBinary(pt)
// }

// func (pt *PlainText) UnmarshalBinary(bits []byte) error {
// 	return ion.Unmarshal(bits, pt)
// }

func (pt *PlainText) MarshalPEM() ([]byte, error) {
	b := pem.Block{
		Type:    pt.Type,
		Headers: pt.Headers,
		Bytes:   pt.PlainTextData,
	}
	return pem.EncodeToMemory(&b), nil
}

func (pt *PlainText) UnmarshalPEM(data []byte) error {
	block, _ := pem.Decode(data)
	pt.Type = block.Type
	pt.Headers = block.Headers
	pt.PlainTextData = block.Bytes
	return nil
}

func (pt *PlainText) PlainText() []byte {
	return pt.PlainTextData
}

func (pt *PlainText) Encrypt() (essence.CipherText, error) {
	// @todo: sanity checks
	cipherTextBytes, err := aeadEncrypt(pt.sharedSecret, pt.PlainText())
	if err != nil {
		return nil, err
	}

	ct := new(CipherText)
	ct.From(pt)
	ct.CipherTextData = cipherTextBytes

	return ct, nil
}

func (pt *PlainText) From(ct essence.CipherText) {
	t, h, ad, _, sig, nonce, eph := ct.Values()
	pt.Type = t
	pt.Headers = h
	pt.AdditionalData = ad
	pt.Signature = sig
	pt.Nonce = nonce
	pt.EphemeralPublicKey = eph
}

func (pt *PlainText) Clone(p2 essence.PlainText) {
	t, h, ad, pl, sig, nonce, eph := pt.Values()
	pt.Type = t
	pt.Headers = h
	pt.AdditionalData = ad
	pt.PlainTextData = pl
	pt.Signature = sig
	pt.Nonce = nonce
	pt.EphemeralPublicKey = eph
}

func (pt *PlainText) Values() (string, map[string]string, []byte, []byte, []byte, []byte, []byte) {
	return pt.Type, pt.Headers, pt.AdditionalData, pt.PlainTextData, pt.Signature, pt.Nonce, pt.EphemeralPublicKey
}

// when sending
func (pt *PlainText) GenerateSharedSecret(randomness io.Reader) error {
	if len(pt.sharedSecret) > 0 {
		//return errors.New("shared secret seems to already exist")
		return nil
	}
	counterPartyPublicKey := pt.recipient
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
	pt.EphemeralPublicKey = ephemeralPublicKey
	pt.sharedSecret = sharedSecretAsSymetricKey
	return nil
}

func (pt *PlainText) FromCipher(ct CipherText) {
	pt.Type = ct.Type
	pt.Headers = ct.Headers
	pt.AdditionalData = ct.AdditionalData
	pt.EphemeralPublicKey = ct.EphemeralPublicKey
	pt.Nonce = ct.Nonce
	pt.Signature = ct.Signature
}
