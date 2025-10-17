package delphi

import (
	"encoding/hex"
	"io"
)

// a subKey is either: a public encryption, public signing, private encryption, or private signing subKey

const subKeySize = 32

type SubKey [subKeySize]byte

var zeroSubKey SubKey

//type PublicSigningKey = ed25519.PublicKey
//type PrivateSigningKey = ed25519.PrivateKey
//
//type PublicEncryptionKey *ecdh.PublicKey
//type PrivateEncryptionKey *ecdh.PrivateKey

//
//type publicSigningKey = subKey
//type PrivateSigningKey = subKey
//type publicEncryptionKey = subKey
//type privateEncryptionKey = subKey

func (s SubKey) String() string {
	return hex.EncodeToString(s[:])
}

func (s SubKey) Bytes() []byte {
	return s[:]
}

func subkeyFromString(s string) (SubKey, error) {
	bin, err := hex.DecodeString(s)
	sk := SubKey{}
	if err != nil {
		return sk, err
	}
	copy(sk[:], bin)
	return sk, nil
}

func newSubKey(randy io.Reader) SubKey {
	sk := SubKey{}
	_, _ = randy.Read(sk[:])
	return sk
}
