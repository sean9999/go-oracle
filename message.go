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
	Encrypt(io.Reader, ed25519.PublicKey) (Message, error)
	Decrypt(ed25519.PrivateKey) (Message, error)
	PlainText() ([]byte, error)
	CipherText() ([]byte, error)
}

// compose a message intended for a peer
func (o *Oracle) Compose(subject string, body []byte, recipient *Peer) *PlainText {
	hdr := map[string]string{
		"subject": subject,
	}
	pt := PlainText{
		Type:          "ORACLE MESSAGE",
		Headers:       hdr,
		PlainTextData: body,
		recipient:     recipient.EncryptionPublicKey,
	}
	return &pt
}

// encrypt PlaintText, returning CipherText
func (o *Oracle) Encrypt(rand io.Reader, pt *PlainText, recipient *Peer) (*CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both

	err := pt.generateSharedSecret(rand)
	if err != nil {
		return nil, err
	}
	return pt.encrypt(rand)
}

// decrypt CipherText, returning PlainText
func (o *Oracle) Decrypt(ct *CipherText, sender *Peer) (*PlainText, error) {
	ct.recipient = o.EncryptionPrivateKey
	err := ct.extractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.decrypt()
}

func (o *Oracle) Sign(pt *PlainText) error {
	pt.generateSharedSecret(o.randomness)
	digest, err := pt.Digest()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(o.SigningPrivateKey, digest)
	pt.Signature = sig
	return nil
}

func (o *Oracle) Verify(pt *PlainText, sender *Peer) bool {
	digest, err := pt.Digest()
	if err != nil {
		return false
	}
	sig := pt.Signature
	return ed25519.Verify(sender.SigningPublicKey, digest, sig)
}
