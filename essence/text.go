package essence

import (
	"encoding"
	"fmt"
)

// CipherText is a blob of encrypted data
// that has a both a binary and ascii-armored (PEM) representation
// Metadata is always visible and unencrypted
type CipherText interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	MarshalPEM() ([]byte, error)
	UnmarshalPEM([]byte) error
	Values() (theType string, headers map[string]string, data []byte)
}

// PlainText is some text with some extra optional metadata
// Metadata is always visible and unencrypted
type PlainText interface {
	Values() (theType string, headers map[string]string, data []byte)
	fmt.Stringer
}
