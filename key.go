package oracle

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/sean9999/go-oracle/essence"
	"golang.org/x/crypto/chacha20poly1305"
)

var ZeroKey x25519.Key

func (o *oracleMachine) GenerateKeys(rand io.Reader) error {
	var pub, priv x25519.Key
	_, _ = io.ReadFull(rand, priv[:])
	x25519.KeyGen(&pub, &priv)
	o.privateKey = priv
	o.publicKey = pub
	return nil
}

func (o *oracleMachine) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	edpriv := ed25519.PrivateKey(o.privateKey[:])
	sig := ed25519.Sign(edpriv, msg)
	return sig, nil
}

func (o *oracleMachine) Verify(pubkey crypto.PublicKey, msg []byte, sig []byte) bool {
	return ed25519.Verify(pubkey.(ed25519.PublicKey), msg, sig)
}

func (o *oracleMachine) Public() crypto.PublicKey {
	return o.publicKey
}

func (o *oracleMachine) PublicKeyAsHex() []byte {
	x := make([]byte, len(o.publicKey))
	hex.Encode(x, o.publicKey[:])
	return x
}

func (o *oracleMachine) PrivateKeyAsHex() []byte {
	x := make([]byte, len(o.privateKey))
	hex.Encode(x, o.privateKey[:])
	return x
}

func (o *oracleMachine) SharedSecret(counterParty essence.Peer) ([]byte, error) {
	//secret, err := curve25519.X25519(o.privateKey[:], counterParty.Public().(ed25519.PublicKey))
	var shared x25519.Key

	counterPartyKey := counterParty.(Peer).PublicKey

	//counterPartyKey := x25519.Key(counterParty.Public().(x25519.Key))
	ok := x25519.Shared(&shared, &o.privateKey, &counterPartyKey)
	fmt.Printf("ok = %t and shared secret: %x\n", ok, shared)
	return shared[:], nil
}

func (o *oracleMachine) Encrypt(rand io.Reader, pt essence.PlainText, recipient essence.Peer) (essence.CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both
	plainData := pt.(*PlainText).Bytes

	secret, err := o.SharedSecret(recipient)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plainData)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	var dst []byte

	cipherBytes := aead.Seal(dst, nonce, plainData, nil)
	ct := NewCipherText(pt.(*PlainText).Type, pt.(*PlainText).Headers, cipherBytes, nil, nil)
	return &ct, nil
}

func (o *oracleMachine) Decrypt(ct essence.CipherText, sender essence.Peer) (essence.PlainText, error) {
	var err error

	secret, err := o.SharedSecret(sender)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	var dst []byte

	encryptedMsg := ct.(*CipherText).Bytes
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
	plainBytes, err := aead.Open(dst, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	pt := NewPlainText(ct.(*CipherText).Type, ct.(*CipherText).Headers, plainBytes, nil, nil)
	return &pt, nil
}
