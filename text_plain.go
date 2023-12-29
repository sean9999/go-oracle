package oracle

import "fmt"

// PlainText has the same structure as CipherText and pem.Block
// but the value held in "Bytes" is plain text.
// PlainText implements [essence.PlainText]
type PlainText struct {
	fields fields
}

func (c *PlainText) Bytes() []byte {
	return c.fields.Bytes
}

func (c *PlainText) Type() string {
	return c.fields.Type
}

func (c *PlainText) Headers() map[string]string {
	return c.fields.Headers
}

func (c *PlainText) Signature() []byte {
	return c.fields.Signature
}

func (c *PlainText) Nonce() []byte {
	return c.fields.Nonce
}

func (pt *PlainText) Values() (string, map[string]string, []byte, []byte, []byte) {
	return pt.fields.Type, pt.fields.Headers, pt.fields.Bytes, pt.fields.Signature, pt.fields.Nonce
}

// PlainText can be output as a string, if you want to see the metadata too.
func (pt *PlainText) String() string {
	kv := fmt.Sprintf("%s:\t%s\n", "type", pt.Type())
	for k, v := range pt.Headers() {
		kv = fmt.Sprintf("%s\n%s:\t%s", kv, k, v)
	}
	pemLike := `
	-----BEGIN PLAINTEXT MESSAGE-----
	%s
	
	%s
	-----END PLAINTEXT MESSAGE-----		
	`
	return fmt.Sprintf(pemLike, kv, string(pt.Bytes()))
}

func NewPlainText(typ string, hdrs map[string]string, b []byte, sig []byte, nonce []byte) PlainText {
	fields := fields{
		Type:      typ,
		Headers:   hdrs,
		Bytes:     b,
		Signature: sig,
		Nonce:     nonce,
	}
	pt := PlainText{fields}
	return pt
}

func NewPlainTextFromCipherText(ct *CipherText) PlainText {
	pt := PlainText{}
	pt.fields = ct.fields
	return pt
}
