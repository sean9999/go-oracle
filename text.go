package oracle

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/amazon-ion/ion-go/ion"
)

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

func (c *CipherText) MarshalPEM() ([]byte, error) {
	block := pem.Block{
		Type:    c.Type,
		Headers: c.Headers,
		Bytes:   c.Bytes,
	}
	pem := pem.EncodeToMemory(&block)
	return pem, nil
}

func (c *CipherText) UnmarshalPEM(txt []byte) error {
	block, _ := pem.Decode(txt)
	c.Type = block.Type
	c.Headers = block.Headers
	c.Bytes = block.Bytes
	return nil
}

func (c *CipherText) Values() (string, map[string]string, []byte) {
	return c.Type, c.Headers, c.Bytes
}

// PlainText has the same structure as CipherText and pem.Block
// but the value held in "Bytes" is plain text.
type PlainText struct {
	Type    string            `json:"subject"`
	Headers map[string]string `json:"metadata"`
	Bytes   []byte            `json:"data"`
}

func (pt *PlainText) Values() (string, map[string]string, []byte) {
	return pt.Type, pt.Headers, pt.Bytes
}

func (pt *PlainText) String() string {
	m := []byte{}
	if len(pt.Headers) > 0 {
		m, _ = json.Marshal(pt.Headers)
	}
	s := `#	%s
	%s
	
	%s
	`
	return fmt.Sprintf(s, pt.Type, string(m), string(pt.Bytes))
}
