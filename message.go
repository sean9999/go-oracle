package oracle

import (
	"crypto/ed25519"
)

// compose a message intended for a peer
func (o *Oracle) Compose(subject string, body []byte) *PlainText {
	hdr := map[string]string{
		"subject": subject,
		"pubkey":  string(o.PublicKeyAsHex()),
	}
	pt := PlainText{
		Type:          "ORACLE MESSAGE",
		Headers:       hdr,
		PlainTextData: body,
	}
	return &pt
}

// encrypt PlaintText, returning CipherText
func (o *Oracle) Encrypt(pt *PlainText, recipient Peer) (*CipherText, error) {
	pt.recipient = recipient.EncryptionKey()
	//pt.Headers["to"] = fmt.Sprintf("%s/%x", recipient.Nickname(), recipient.EncryptionKey().Bytes())
	pt.Headers["from"] = o.Nickname()
	pt.Headers["to"] = recipient.Nickname()
	err := pt.ensureSharedSecret(o.randomness)
	if err != nil {
		return nil, err
	}
	return pt.encrypt(o.randomness)
}

// decrypt CipherText, returning PlainText
func (o *Oracle) Decrypt(ct *CipherText) (*PlainText, error) {
	ct.recipient = o.encryptionPrivateKey
	err := ct.extractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.decrypt()
}

func (o *Oracle) Sign(pt *PlainText) error {
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

func (o *Oracle) Verify(pt *PlainText, sender Peer) bool {
	digest, err := pt.Digest()
	if err != nil {
		return false
	}
	return ed25519.Verify(sender.SigningKey(), digest, pt.Signature)
}
