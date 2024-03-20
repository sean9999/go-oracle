package essence

import (
	"fmt"
	"io"
)

// Type               string            `json:"type" ion:"type"`
// Headers            map[string]string `json:"headers" ion:"headers"`
// AdditionalData     []byte            `json:"aad" ion:"aad"`
// PlainText          []byte            `json:"plaintext" ion:"plaintext"`
// Signature          []byte            `json:"signature" ion:"signature"`
// Nonce              []byte            `json:"nonce" ion:"nonce"`
// EphemeralPublicKey []byte            `json:"ephpub" ion:"ephpub"`
// recipient          *ecdh.PublicKey
// sender             *ecdh.PrivateKey
// sharedSecret       []byte

type PlainText interface {
	From(CipherText)
	Clone(PlainText)
	PlainText() []byte
	Encrypt() (CipherText, error)
	GenerateSharedSecret(io.Reader) error
	//Nonce() []byte
	//AdditionalData() []byte
	Values() (theType string, hdrs map[string]string, ad []byte, pt []byte, sig []byte, nonce []byte, ephem []byte)
	fmt.Stringer
	MarshalPEM() ([]byte, error)
	UnmarshalPEM(data []byte) error
}

type CipherText interface {
	Clone(CipherText)
	From(PlainText)
	ExtractSharedSecret() error
	CipherText() []byte
	Decrypt() (PlainText, error)
	Values() (theType string, hdrs map[string]string, ad []byte, ct []byte, sig []byte, nonce []byte, ephem []byte)
	//Nonce() []byte
	//AdditionalData() []byte
	MarshalPEM() ([]byte, error)
	UnmarshalPEM(data []byte) error
}
