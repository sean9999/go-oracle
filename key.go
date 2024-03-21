package oracle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
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
	o.publicKey = priv.PublicKey()
	return nil
}

func (o *Oracle) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	edpriv := ed25519.PrivateKey(o.privateKey.Bytes())
	sig := ed25519.Sign(edpriv, msg)
	err := recover()
	return sig, err.(error)
}

func (o *Oracle) Verify(pubkey crypto.PublicKey, msg []byte, sig []byte) bool {
	return ed25519.Verify(pubkey.(ed25519.PublicKey), msg, sig)
}

func (o *Oracle) Public() crypto.PublicKey {
	return o.publicKey
}

func (o *Oracle) PublicKeyAsHex() []byte {
	material := o.publicKey.Bytes()
	x := make([]byte, len(material))
	hex.Encode(x, material)
	return x
}

func (o *Oracle) Encrypt(rand io.Reader, pt *PlainText, recipient *Peer) (*CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both

	err := pt.GenerateSharedSecret(rand)
	if err != nil {
		return nil, err
	}
	return pt.Encrypt()
}

func (o *Oracle) Decrypt(ct *CipherText, sender *Peer) (*PlainText, error) {
	ct.recipient = o.privateKey
	err := ct.ExtractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.Decrypt()
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
