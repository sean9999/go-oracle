package oracle

import (
	"crypto/ed25519"
	"io"
)

type Message interface {
	Digest() ([]byte, error)
	//Validate() error
	Sign(io.Reader, ed25519.PrivateKey)
	Verify(ed25519.PublicKey) bool
	Encrypt(io.Reader, ed25519.PublicKey) (*CipherText, error)
	Decrypt(ed25519.PrivateKey) (*PlainText, error)
	PlainText() ([]byte, error)
	CipherText() ([]byte, error)
}

// compose a message intended for a peer
func (o *oracle) Compose(subject string, body []byte) *PlainText {
	hdr := map[string]string{
		"subject": subject,
	}
	pt := PlainText{
		Type:          "ORACLE MESSAGE",
		Headers:       hdr,
		PlainTextData: body,
	}
	return &pt
}

// encrypt PlaintText, returning CipherText
func (o *oracle) Encrypt(pt *PlainText, recipient Peer) (*CipherText, error) {
	pt.recipient = recipient.EncryptionKey()
	err := pt.generateSharedSecret(o.randomness)
	if err != nil {
		return nil, err
	}
	return pt.encrypt(o.randomness)
}

// decrypt CipherText, returning PlainText
func (o *oracle) Decrypt(ct *CipherText) (*PlainText, error) {
	ct.recipient = o.encryptionPrivateKey
	err := ct.extractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.decrypt()
}

func (o *oracle) Sign(pt *PlainText) error {
	//pt.generateSharedSecret(o.randomness)
	pt.generateNonce(o.randomness)
	digest, err := pt.Digest()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(o.signingPrivateKey, digest)
	pt.Signature = sig
	return nil
}

func (o *oracle) Verify(pt *PlainText, sender Peer) bool {
	digest, err := pt.Digest()
	if err != nil {
		return false
	}
	sig := pt.Signature
	return ed25519.Verify(sender.SigningKey(), digest, sig)
}
