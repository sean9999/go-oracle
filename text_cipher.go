package oracle

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/amazon-ion/ion-go/ion"
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
	sharedSecret       []byte
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
	if ct == nil {
		return nil, errors.New("CipherText was nil")
	}
	ct.Headers["eph"] = hex.EncodeToString(ct.EphemeralPublicKey)
	if ct.Signature != nil {
		ct.Headers["sig"] = hex.EncodeToString(ct.Signature)
	}
	if ct.Nonce != nil {
		ct.Headers["nonce"] = hex.EncodeToString(ct.Nonce)
	}
	if ct.AdditionalData != nil {
		ct.Headers["aad"] = hex.EncodeToString(ct.AdditionalData)
	}
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

// create CipherText from PlainText
// This does _not_ peform encryption.
// you must handle PlainTextData and CipherTextData fields seperately.
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

func (ct *CipherText) decrypt() (*PlainText, error) {
	plainTextData, err := decrypt(ct.sharedSecret, UniversalNonce, ct.CipherTextData, nil)
	if err != nil {
		return nil, err
	}
	pt := new(PlainText)
	pt.From(ct)
	pt.PlainTextData = plainTextData
	return pt, nil
}

// when receiving
func (ct *CipherText) extractSharedSecret() error {
	sharedSecret, err := extractSharedSecret(ct.EphemeralPublicKey, ct.recipient.Bytes(), ct.recipient.PublicKey().Bytes())
	if err != nil {
		return err
	}
	ct.sharedSecret = sharedSecret
	return nil

}
