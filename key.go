package oracle

import (
	"crypto"
	"crypto/ecdh"
	"encoding/hex"
	"io"
)

var ZeroPrivateKey *ecdh.PrivateKey = new(ecdh.PrivateKey)
var ZeroPublicKey *ecdh.PublicKey = new(ecdh.PublicKey)

func (o *Oracle) GenerateKeys(rand io.Reader) error {
	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(rand)
	if err != nil {
		return err
	}
	o.privateKey = priv
	o.PublicKey = priv.PublicKey()
	return nil
}

func (o *Oracle) Public() crypto.PublicKey {
	return o.PublicKey
}

func (o *Oracle) PublicKeyAsHex() []byte {
	material := o.PublicKey.Bytes()
	x := make([]byte, len(material))
	hex.Encode(x, material)
	return x
}

func PublicKeyFromHex(hexData []byte) (*ecdh.PublicKey, error) {
	bin := make([]byte, 0)
	_, err := hex.Decode(bin, hexData)
	if err != nil {
		return nil, err
	}
	ed := ecdh.X25519()
	k, err := ed.NewPublicKey(bin)
	if err != nil {
		return nil, err
	}
	return k, nil
}
