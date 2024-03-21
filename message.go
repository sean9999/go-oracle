package oracle

import (
	"io"
)

// compose a message intended for a peer
func (o *Oracle) Compose(subject string, body []byte, recipient *Peer) *PlainText {
	hdr := map[string]string{
		"subject": subject,
	}
	pt := PlainText{
		Type:          "ORACLE MESSAGE",
		Headers:       hdr,
		PlainTextData: body,
		recipient:     recipient.PublicKey,
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
	ct.recipient = o.privateKey
	err := ct.extractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.decrypt()
}
