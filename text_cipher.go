package oracle

import (
	"encoding/pem"

	"github.com/amazon-ion/ion-go/ion"
)

// CipherText represents encrypted data and associated metadata.
// It implements [essence.CipherText]
type CipherText struct {
	fields fields
}

func NewCipherText(typ string, hdrs map[string]string, b []byte, sig []byte, nonce []byte) CipherText {
	fields := fields{
		Type:      typ,
		Headers:   hdrs,
		Bytes:     b,
		Signature: sig,
		Nonce:     nonce,
	}
	ct := CipherText{fields}
	return ct
}

func (c *CipherText) Bytes() []byte {
	return c.fields.Bytes
}

func (c *CipherText) Type() string {
	return c.fields.Type
}

func (c *CipherText) Headers() map[string]string {
	return c.fields.Headers
}

func (c *CipherText) Signature() []byte {
	return c.fields.Signature
}

func (c *CipherText) Nonce() []byte {
	return c.fields.Nonce
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
		Type:    c.Type(),
		Headers: c.Headers(),
		Bytes:   c.Bytes(),
	}
	pem := pem.EncodeToMemory(&block)
	return pem, nil
}

// unmarshal a PEM file
func (c *CipherText) UnmarshalPEM(txt []byte) error {
	block, _ := pem.Decode(txt)
	c.fields.Type = block.Type
	c.fields.Headers = block.Headers
	c.fields.Bytes = block.Bytes
	return nil
}

// a convenient way to export all the values
func (c *CipherText) Values() (string, map[string]string, []byte, []byte, []byte) {
	return c.fields.Type, c.fields.Headers, c.fields.Bytes, c.fields.Signature, c.fields.Nonce
}

func NewCipherTextFromPlainText(pt *PlainText) CipherText {
	ct := CipherText{}
	ct.fields = pt.fields
	return ct
}
