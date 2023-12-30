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
}

// PlainText is some text with some extra optional metadata
// Metadata is always visible and unencrypted
type PlainText interface {
	fmt.Stringer
}
