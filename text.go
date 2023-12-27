package oracle

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/amazon-ion/ion-go/ion"
)

// CipherText represents encrypted data and associated metadata.
// It implements [essence.CipherText]
type CipherText struct {
	Type    string            `json:"subject" ion:"subject"`
	Headers map[string]string `json:"metadata" ion:"metadata"`
	Bytes   []byte            `json:"data" ion:"data"`
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
func (c *CipherText) Values() (string, map[string]string, []byte) {
	return c.Type, c.Headers, c.Bytes
}

// PlainText has the same structure as CipherText and pem.Block
// but the value held in "Bytes" is plain text.
// PlainText implements [essence.PlainText]
type PlainText struct {
	Type    string            `json:"subject"`
	Headers map[string]string `json:"metadata"`
	Bytes   []byte            `json:"data"`
}

func (pt *PlainText) Values() (string, map[string]string, []byte) {
	return pt.Type, pt.Headers, pt.Bytes
}

// PlainText can be output as a string, if you want to see the metadata too.
func (pt *PlainText) String() string {
	m := []byte{}
	if len(pt.Headers) > 0 {
		m, _ = json.Marshal(pt.Headers)
	}
	s := `type:\t%s
	headers:\t%s
	
	message:\%s
	`
	return fmt.Sprintf(s, pt.Type, string(m), string(pt.Bytes))
}
