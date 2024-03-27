package oracle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
)

var ZeroPrivateKey *ecdh.PrivateKey = new(ecdh.PrivateKey)
var ZeroPublicKey *ecdh.PublicKey = new(ecdh.PublicKey)

var ErrKeysAlreadyExist = errors.New("crypto keys already exists")

func (o *Oracle) GenerateKeys(rand io.Reader) error {
	if o.encryptionPrivateKey != nil {
		return ErrKeysAlreadyExist
	}
	if o.signingPrivateKey != nil {
		return ErrKeysAlreadyExist
	}
	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(rand)
	if err != nil {
		return err
	}
	//	@todo: we can see that only EncryptionPrivateKey is unique
	//	everything else is derived.
	o.encryptionPrivateKey = priv
	o.EncryptionPublicKey = priv.PublicKey()
	o.signingPrivateKey = ed25519.NewKeyFromSeed(priv.Bytes())
	o.SigningPublicKey = o.signingPrivateKey.Public().(ed25519.PublicKey)

	return nil
}

func (o *Oracle) Public() crypto.PublicKey {
	return o.EncryptionPublicKey
}

func (o *Oracle) PublicKeyAsHex() []byte {
	material := o.EncryptionPublicKey.Bytes()
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
