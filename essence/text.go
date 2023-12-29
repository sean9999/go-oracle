package essence

import (
	"encoding"
	"fmt"
)

type genericText interface {
	Values() (theType string, headers map[string]string, data []byte, sig []byte, nonce []byte)
	Type() string
	Headers() map[string]string
	Bytes() []byte
	Signature() []byte
	Nonce() []byte
}

// CipherText is a blob of encrypted data
// that has a both a binary and ascii-armored (PEM) representation
// Metadata is always visible and unencrypted
type CipherText interface {
	genericText
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	MarshalPEM() ([]byte, error)
	UnmarshalPEM([]byte) error
}

// PlainText is some text with some extra optional metadata
// Metadata is always visible and unencrypted
type PlainText interface {
	genericText
	fmt.Stringer
}
