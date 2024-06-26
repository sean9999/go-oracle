package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	"github.com/amazon-ion/ion-go/ion"
	"golang.org/x/crypto/chacha20poly1305"
)

// PlainText includes payload and metadata for encrypting and sending
type PlainText struct {
	Type               string            `json:"type" ion:"type"`
	Headers            map[string]string `json:"headers" ion:"headers"`
	AdditionalData     []byte            `json:"aad" ion:"aad"`
	PlainTextData      []byte            `json:"plaintext" ion:"plaintext"`
	Signature          []byte            `json:"signature" ion:"signature"`
	Nonce              []byte            `json:"nonce" ion:"nonce"`
	EphemeralPublicKey []byte            `json:"ephpub" ion:"ephpub"`
	recipient          *ecdh.PublicKey
	//sender             *ecdh.PrivateKey
	sharedSecret []byte
}

func (pt *PlainText) Sign(randy io.Reader, priv ed25519.PrivateKey) error {
	pt.generateNonce(randy)
	digest, err := pt.Digest()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, digest)
	pt.Signature = sig
	return nil
}

func (pt *PlainText) Verify(pub ed25519.PublicKey) bool {
	digest, err := pt.Digest()
	if err != nil {
		return false
	}
	sig := pt.Signature
	return ed25519.Verify(pub, digest, sig)
}

func (pt *PlainText) PlainText() ([]byte, error) {
	return pt.PlainTextData, nil
}

func (pt *PlainText) CipherText() ([]byte, error) {
	return nil, errors.New("plain text has no ciphertext")
}

func (pt *PlainText) Digest() ([]byte, error) {
	if pt.EphemeralPublicKey == nil && pt.Nonce == nil {
		return nil, errors.New("digest cannot be created because of lack of randomness")
	}
	bin := make([]byte, 0)
	if pt.EphemeralPublicKey != nil {
		bin = append(bin, pt.EphemeralPublicKey...)
	}
	bin = append(bin, pt.PlainTextData...)
	if pt.Nonce != nil {
		bin = append(bin, pt.Nonce...)
	}
	dig := sha256.New()
	dig.Write(bin)
	return dig.Sum(nil), nil
}

func (pt *PlainText) String() string {
	j, _ := json.Marshal(pt)
	return string(j)
}

func (pt *PlainText) MarshalPEM() ([]byte, error) {
	var m map[string]string
	if pt.Headers == nil {
		m = map[string]string{}
	} else {
		m = pt.Headers
	}
	if pt.Signature != nil {
		m["sig"] = hex.EncodeToString(pt.Signature)
	}
	if pt.EphemeralPublicKey != nil {
		m["eph"] = hex.EncodeToString(pt.EphemeralPublicKey)
	}
	if pt.Nonce != nil {
		m["nonce"] = hex.EncodeToString(pt.Nonce)
	}
	if len(pt.AdditionalData) > 0 {
		m["aad"] = hex.EncodeToString(pt.AdditionalData)
	}
	b := pem.Block{
		Type:    pt.Type,
		Headers: m,
		Bytes:   pt.PlainTextData,
	}
	return pem.EncodeToMemory(&b), nil
}

func (pt *PlainText) UnmarshalPEM(data []byte) error {
	if data == nil {
		return errors.New("nil data")
	}
	block, _ := pem.Decode(data)
	pt.Type = block.Type
	pt.Headers = block.Headers
	pt.PlainTextData = block.Bytes
	sigHex, hasSig := block.Headers["sig"]
	if hasSig {
		sigBin, err := hex.DecodeString(sigHex)
		if err != nil {
			return err
		}
		pt.Signature = sigBin
	}
	ephHex, hasEph := block.Headers["eph"]
	if hasEph {
		ephBin, err := hex.DecodeString(ephHex)
		if err != nil {
			return err
		}
		pt.EphemeralPublicKey = ephBin
	}
	nonceHex, hasNonce := block.Headers["nonce"]
	if hasNonce {
		nonceBin, err := hex.DecodeString(nonceHex)
		if err != nil {
			return err
		}
		pt.Nonce = nonceBin
	}
	aadHex, hasAad := block.Headers["aad"]
	if hasAad {
		aadBin, err := hex.DecodeString(aadHex)
		if err != nil {
			return err
		}
		pt.AdditionalData = aadBin
	}
	return nil
}

func (pt *PlainText) MarshalIon() ([]byte, error) {
	return ion.MarshalBinary(pt)
}

func (pt *PlainText) UnmarshalIon(bin []byte) error {
	return ion.Unmarshal(bin, pt)
}

func (pt *PlainText) encrypt(randy io.Reader) (*CipherText, error) {
	// @todo: sanity checks
	pt.ensureSharedSecret(randy)
	if pt.EphemeralPublicKey == nil {
		return nil, ErrNoEphemeralKey
	}
	cipherTextBytes, err := encrypt(pt.sharedSecret, pt.PlainTextData)
	if err != nil {
		return nil, err
	}
	ct := new(CipherText)
	ct.From(pt)
	ct.CipherTextData = cipherTextBytes
	return ct, nil
}

func (pt *PlainText) From(ct *CipherText) {
	pt.Type = ct.Type
	pt.Headers = ct.Headers
	pt.AdditionalData = ct.AdditionalData
	pt.Signature = ct.Signature
	pt.Nonce = ct.Nonce
	pt.EphemeralPublicKey = ct.EphemeralPublicKey
}

func (pt *PlainText) Clone(p2 *PlainText) {
	pt.Type = p2.Type
	pt.Headers = p2.Headers
	pt.AdditionalData = p2.AdditionalData
	pt.PlainTextData = p2.PlainTextData
	pt.Signature = p2.Signature
	pt.Nonce = p2.Nonce
	pt.EphemeralPublicKey = p2.EphemeralPublicKey
}

func (pt *PlainText) generateNonce(randomness io.Reader) error {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := randomness.Read(nonce); err != nil {
		return err
	}
	pt.Nonce = nonce
	return nil
}

// when sending
func (pt *PlainText) ensureSharedSecret(randomness io.Reader) error {
	if len(pt.sharedSecret) > 0 {
		//	secret already exists. Just return
		return nil
	}
	if pt.recipient == nil {
		return errors.New("cannot generate shared secret with nil recipient")
	}
	sec, ephkey, err := generateSharedSecret(pt.recipient, randomness)
	pt.EphemeralPublicKey = ephkey
	pt.sharedSecret = sec
	return err
}
