package oracle

import (
	"encoding/pem"

	"github.com/amazon-ion/ion-go/ion"
)

// CipherText represents encrypted data and associated metadata.
// It implements [essence.CipherText]
type CipherText struct {
	Type      string            `json:"subject" ion:"subject"`
	Headers   map[string]string `json:"metadata" ion:"metadata"`
	Bytes     []byte            `json:"data" ion:"data"`
	Signature []byte            `json:"sig" ion:"sig"`
	Nonce     []byte            `json:"nonce" ion:"nonce"`
}

func NewCipherText(typ string, hdrs map[string]string, b []byte, sig []byte, nonce []byte) CipherText {
	ct := CipherText{
		Type:      typ,
		Headers:   hdrs,
		Bytes:     b,
		Signature: sig,
		Nonce:     nonce,
	}
	return ct
}

func (c *CipherText) MarshalBinary() ([]byte, error) {
	return ion.MarshalBinary(c)
}

func (c *CipherText) UnmarshalBinary(bin []byte) error {
	return ion.Unmarshal(bin, c)
}

// MarshalPEM marshals the CipherText into ASCII-armored text
func (c *CipherText) MarshalPEM() ([]byte, error) {
	block := pem.Block{
		Type:    c.Type,
		Headers: c.Headers,
		Bytes:   c.Bytes,
	}
	pem := pem.EncodeToMemory(&block)
	return pem, nil
}

// unmarshal a PEM file
func (c *CipherText) UnmarshalPEM(txt []byte) error {
	block, _ := pem.Decode(txt)
	c.Type = block.Type
	c.Headers = block.Headers
	c.Bytes = block.Bytes
	return nil
}

// a convenient way to export all the values
func (c *CipherText) Values() (string, map[string]string, []byte, []byte, []byte) {
	return c.Type, c.Headers, c.Bytes, c.Signature, c.Nonce
}

func NewCipherTextFromPlainText(pt *PlainText) CipherText {
	ct := CipherText{
		Type:      pt.Type,
		Headers:   pt.Headers,
		Signature: pt.Signature,
		Nonce:     pt.Nonce,
	}

	return ct
}
