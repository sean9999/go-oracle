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

// sign a byte slice
// func (o *Oracle) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) []byte {
// 	edpriv := ed25519.PrivateKey(o.privateKey.Bytes())
// 	sig := ed25519.Sign(edpriv, msg)
// 	return sig
// }

// // verify the signature on a byte slice
// func (o *Oracle) Verify(pubkey crypto.PublicKey, msg []byte, sig []byte) bool {
// 	return ed25519.Verify(pubkey.(ed25519.PublicKey), msg, sig)
// }

// encrypt PlaintText, returning CipherText
func (o *Oracle) Encrypt(rand io.Reader, pt *PlainText, recipient *Peer) (*CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both

	err := pt.generateSharedSecret(rand)
	if err != nil {
		return nil, err
	}
	return pt.Encrypt(rand)
}

// decrypt CipherText, returning PlainText
func (o *Oracle) Decrypt(ct *CipherText, sender *Peer) (*PlainText, error) {
	ct.recipient = o.privateKey
	err := ct.ExtractSharedSecret()
	if err != nil {
		return nil, err
	}
	return ct.Decrypt()
}
