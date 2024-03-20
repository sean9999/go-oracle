package oracle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"io"

	"github.com/sean9999/go-oracle/essence"
)

var ZeroPrivateKey *ecdh.PrivateKey = new(ecdh.PrivateKey)
var ZeroPublicKey *ecdh.PublicKey = new(ecdh.PublicKey)

func (o *oracleMachine) GenerateKeys(rand io.Reader) error {
	ed := ecdh.X25519()
	priv, err := ed.GenerateKey(rand)
	if err != nil {
		return err
	}
	o.privateKey = priv
	o.publicKey = priv.PublicKey()
	return nil
}

func (o *oracleMachine) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	edpriv := ed25519.PrivateKey(o.privateKey.Bytes())
	sig := ed25519.Sign(edpriv, msg)
	err := recover()
	return sig, err.(error)
}

func (o *oracleMachine) Verify(pubkey crypto.PublicKey, msg []byte, sig []byte) bool {
	return ed25519.Verify(pubkey.(ed25519.PublicKey), msg, sig)
}

func (o *oracleMachine) Public() crypto.PublicKey {
	return o.publicKey
}

func (o *oracleMachine) PublicKeyAsHex() []byte {
	material := o.publicKey.Bytes()
	x := make([]byte, len(material))
	hex.Encode(x, material)
	return x
}

func (o *oracleMachine) Encrypt(rand io.Reader, pt essence.PlainText, recipient essence.Peer) (essence.CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both

	err := pt.GenerateSharedSecret(rand)
	if err != nil {
		return nil, err
	}
	return pt.Encrypt()
}

func (o *oracleMachine) Decrypt(ct essence.CipherText, sender essence.Peer) (essence.PlainText, error) {
	ct.recipient = o.privateKey
	err := ct.ExtractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.Decrypt()
}
