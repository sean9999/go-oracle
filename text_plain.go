package oracle

import "fmt"

// PlainText has the same structure as CipherText and pem.Block
// but the value held in "Bytes" is plain text.
// PlainText implements [essence.PlainText]
type PlainText struct {
	Type      string            `json:"subject" ion:"subject"`
	Headers   map[string]string `json:"metadata" ion:"metadata"`
	Bytes     []byte            `json:"data" ion:"data"`
	Signature []byte            `json:"sig" ion:"sig"`
	Nonce     []byte            `json:"nonce" ion:"nonce"`
}

func (pt *PlainText) Values() (string, map[string]string, []byte) {
	return pt.Type, pt.Headers, pt.Bytes
}

// PlainText can be output as a string, if you want to see the metadata too.
func (pt *PlainText) String() string {
	kv := fmt.Sprintf("%s:\t%s\n", "type", pt.Type)
	for k, v := range pt.Headers {
		kv = fmt.Sprintf("%s\n%s:\t%s", kv, k, v)
	}
	pemLike := `
	-----BEGIN PLAINTEXT MESSAGE-----
	%s
	
	%s
	-----END PLAINTEXT MESSAGE-----		
	`
	return fmt.Sprintf(pemLike, kv, string(pt.Bytes))
}

func NewPlainText(typ string, hdrs map[string]string, b []byte, sig []byte, nonce []byte) PlainText {
	pt := PlainText{
		Type:      typ,
		Headers:   hdrs,
		Bytes:     b,
		Signature: sig,
		Nonce:     nonce,
	}
	return pt
}

func NewPlainTextFromCipherText(ct *CipherText) PlainText {
	pt := PlainText{
		Type:      ct.Type,
		Headers:   ct.Headers,
		Signature: ct.Signature,
		Nonce:     ct.Nonce,
	}
	return pt
}
