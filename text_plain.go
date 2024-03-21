package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	"github.com/amazon-ion/ion-go/ion"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var ErrNoEphemeralKey = errors.New("no ephemeral key")

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

// func ComposeLetter(recipient *ecdh.PublicKey, subject string, body []byte) *PlainText {
// 	hdrs := map[string]string{
// 		"subject": subject,
// 	}
// 	pt := PlainText{
// 		Headers:       hdrs,
// 		Type:          "ORACLE MESSAGE",
// 		PlainTextData: body,
// 		recipient:     recipient,
// 	}
// 	return &pt
// }

// func (pt *PlainText) UnmarshalText(jsonText []byte) error {
// 	return json.Unmarshal(jsonText, pt)
// }

// func (pt *PlainText) MarshalText() ([]byte, error) {
// 	return json.Marshal(pt)
// }

func (pt *PlainText) String() string {
	j, _ := json.Marshal(pt)
	return string(j)
}

func (pt *PlainText) MarshalPEM() ([]byte, error) {
	pt.Headers["eph"] = string(pt.EphemeralPublicKey)
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

func (pt *PlainText) MarshalIon() ([]byte, error) {
	return ion.MarshalBinary(pt)
}

func (pt *PlainText) UnmarshalIon(bin []byte) error {
	return ion.Unmarshal(bin, pt)
}

func (pt *PlainText) Encrypt(randy io.Reader) (*CipherText, error) {
	// @todo: sanity checks
	pt.generateSharedSecret(randy)
	if pt.EphemeralPublicKey == nil {
		return nil, ErrNoEphemeralKey
	}
	cipherTextBytes, err := aeadEncrypt(pt.sharedSecret, pt.PlainTextData)
	if err != nil {
		return nil, err
	}
	ct := new(CipherText)
	ct.From(pt)
	ct.CipherTextData = cipherTextBytes
	return ct, nil
}

func (pt *PlainText) Sign(randy io.Reader, signer *Oracle) {
	pt.Signature = signer.Sign(randy, pt.PlainTextData, nil)
}

func (pt *PlainText) Verify(sender Peer) bool {
	return ed25519.Verify(sender.PublicKey.Bytes(), pt.PlainTextData, pt.Signature)
}

func (pt *PlainText) From(ct *CipherText) {
	pt.Type = ct.Type
	pt.Headers = ct.Headers
	pt.AdditionalData = ct.AdditionalData
	pt.Signature = ct.Signature
	pt.Nonce = ct.Nonce
	pt.EphemeralPublicKey = ct.EphemeralPublicKey
}

func (pt *PlainText) Clone(p2 *PlainText) {
	pt.Type = p2.Type
	pt.Headers = p2.Headers
	pt.AdditionalData = p2.AdditionalData
	pt.PlainTextData = p2.PlainTextData
	pt.Signature = p2.Signature
	pt.Nonce = p2.Nonce
	pt.EphemeralPublicKey = p2.EphemeralPublicKey
}

// when sending
func (pt *PlainText) generateSharedSecret(randomness io.Reader) error {
	if len(pt.sharedSecret) > 0 {
		//	no need to run. Just return
		//	@todo: somehow verify? or maybe throw an error?
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
	h := hkdf.New(sha256.New, sharedSecretAsEdwards, salt, []byte(GLOBAL_SALT))
	sharedSecretAsSymetricKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecretAsSymetricKey); err != nil {
		return err
	}
	pt.EphemeralPublicKey = ephemeralPublicKey
	pt.sharedSecret = sharedSecretAsSymetricKey
	return nil
}
