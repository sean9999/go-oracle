package oracle

import (
	"crypto"
	"crypto/ecdh"
	"errors"
	"io"
)

var ZeroPrivateKey *ecdh.PrivateKey = new(ecdh.PrivateKey)
var ZeroPublicKey *ecdh.PublicKey = new(ecdh.PublicKey)

var ErrKeysAlreadyExist = errors.New("crypto keys already exists")

func (o *Oracle) GenerateKeys(rand io.Reader) error {

	m := KeyMatieral{}.Generate(rand)

	o.Material = m

	return nil
}

func (o *Oracle) Public() crypto.PublicKey {
	return o.PublicEncryptionKey()
}

func (o *Oracle) PublicKeyAsHex() []byte {
	x, _ := o.AsPeer().MarshalHex()
	return x
}

// func PublicKeyFromHex(hexData []byte) (*ecdh.PublicKey, error) {
// 	bin := make([]byte, 0)
// 	_, err := hex.Decode(bin, hexData)
// 	if err != nil {
// 		return nil, err
// 	}
// 	ed := ecdh.X25519()
// 	k, err := ed.NewPublicKey(bin)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return k, nil
// }
