package message

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sean9999/go-oracle/v3/delphi"
	"io"
	"runtime"

	smap "github.com/sean9999/go-stable-map"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSize

type Message struct {
	PlainText    []byte `json:"plain,omitempty" msgpack:"plain,omitempty"`
	CipherText   []byte `json:"ciph,omitempty" msgpack:"ciph,omitempty"`
	AAD          []byte `json:"aad,omitempty" msgpack:"aad,omitempty"`
	Nonce        []byte `json:"nonce,omitempty" msgpack:"nonce,omitempty"`
	EphemeralKey []byte `json:"eph,omitempty" msgpack:"eph,omitempty"`
	Signature    []byte `json:"sig,omitempty" msgpack:"sig,omitempty"`
}

func NewMessage(randy io.Reader) *Message {
	msg := Message{}
	if randy != nil {
		nonce := make([]byte, NonceSize)
		_, _ = randy.Read(nonce)
		msg.Nonce = nonce
	}
	return &msg
}

var ErrBadMessage = errors.New("bad message")

// Validate cheks a Message to see if it looks right.
func (msg *Message) Validate() error {
	if msg.IsPlain() && msg.IsEncrypted() {
		return fmt.Errorf("%w. both encrypted and plain", ErrBadMessage)
	}
	if !msg.IsPlain() && !msg.IsEncrypted() {
		return fmt.Errorf("%w. neither encrypted nor plain", ErrBadMessage)
	}
	if msg.IsEncrypted() && msg.Nonce == nil {
		return fmt.Errorf("%w. encrypted data, but no nonce", ErrBadMessage)
	}
	if msg.Signature != nil && msg.Nonce == nil {
		return fmt.Errorf("%w. signature, but no nonce", ErrBadMessage)
	}
	return nil
}

func (msg *Message) MustValidate() {
	err := msg.Validate()
	if err != nil {
		panic(err)
	}
}

func (msg *Message) Digest() ([]byte, error) {
	err := msg.Validate()
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	sum := make([]byte, 0)
	sum = append(sum, msg.Nonce...)
	if msg.IsEncrypted() {
		sum = append(sum, msg.CipherText...)
	} else {
		sum = append(sum, msg.PlainText...)
	}
	sum = append(sum, msg.AAD...)
	return hash.Sum(sum), nil
}

func (msg *Message) Serialize() []byte {
	//	since we know what a message is made of, we know that msgpack.Marshal will always pass
	//	There is a fuzzing test to test this assumption
	b, _ := msgpack.Marshal(msg)
	return b
}

func (msg *Message) Deserialize(b []byte) {
	err := msgpack.Unmarshal(b, msg)
	if err != nil {
		panic(err)
	}
}

// asBytes takes a thing and returns it as a byte-slice, or error.
func asBytes(thing any) ([]byte, error) {
	data, ok := thing.([]byte)
	if ok {
		return data, nil
	}
	byter, ok := thing.(interface {
		Bytes() []byte
	})
	if ok {
		return byter.Bytes(), nil
	}
	marshaller, ok := thing.(encoding.BinaryMarshaler)
	if ok {
		return marshaller.MarshalBinary()
	}
	//	encode directly to binary and hope for the best
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, thing)
	return buf.Bytes(), err
}

type Decrypter interface {
	Decrypt([]byte, []byte, []byte, []byte) ([]byte, error)
}

func (msg *Message) Decrypt(recipient Decrypter) error {
	plainText, err := recipient.Decrypt(msg.CipherText, msg.EphemeralKey, msg.Nonce, msg.AAD)
	if err != nil {
		return err
	}
	msg.PlainText = plainText
	msg.CipherText = nil
	return nil
}

type SymmetricEncrypter interface {
	Seal([]byte, []byte, []byte, []byte) ([]byte, error)
	GenerateSharedSecret(io.Reader, crypto.PublicKey) ([]byte, []byte, error)
}

type secretSealer interface {
	Seal([]byte, []byte, []byte, []byte) ([]byte, error)
	GenerateSharedSecret(io.Reader, delphi.PublicKey) ([]byte, []byte, error)
}

func (msg *Message) Encrypt(randy io.Reader, recipient delphi.PublicKey, e secretSealer) error {

	if len(msg.Nonce) == 0 {
		msg.Nonce = make([]byte, NonceSize)
		randy.Read(msg.Nonce)
	}
	if msg.PlainText == nil {
		return errors.New("no plain text to encrypt")
	}

	sec, eph, err := e.GenerateSharedSecret(randy, recipient)
	if err != nil {
		return fmt.Errorf("could not encrypt. %w", err)
	}
	cipherText, err := e.Seal(sec, msg.PlainText, msg.Nonce, msg.AAD)
	if err != nil {
		return fmt.Errorf("could not encrypt. %w", err)
	}
	msg.EphemeralKey = eph
	msg.CipherText = cipherText
	msg.PlainText = nil

	//	run garbage collection because we don't want to leak the plain text
	runtime.GC()

	return nil
}

func (msg *Message) Sign(signer crypto.Signer) error {
	dig, err := msg.Digest()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(nil, dig, nil)
	if err != nil {
		return err
	}
	msg.Signature = sig
	return nil
}

type Verifier interface {
	Verify(pubKey crypto.PublicKey, digest []byte, signature []byte) bool
}

func (msg *Message) Verify(pubKey crypto.PublicKey, v Verifier) bool {
	digest, err := msg.Digest()

	if err != nil {
		return false
	}
	return v.Verify(pubKey, digest, msg.Signature)
}

//
//func (msg *Message) VerifyBad(pubKey crypto.PublicKey) bool {
//	pubBytes, err := asBytes(pubKey)
//	if err != nil {
//		return false
//	}
//	if msg.Signature == nil {
//		return false
//	}
//	digest, err := msg.Digest()
//	if err != nil {
//		return false
//	}
//	return ed25519.Verify(pubBytes, digest, msg.Signature)
//}

func (msg *Message) IsEncrypted() bool {
	return msg.CipherText != nil
}

func (msg *Message) IsPlain() bool {
	return msg.PlainText != nil
}

func (msg *Message) Body() []byte {
	msg.MustValidate()
	if msg.IsEncrypted() {
		return msg.CipherText
	}
	return msg.PlainText
}

func aadToHeaders(aad []byte) (headers map[string]string) {
	headers = make(map[string]string)
	sm := smap.From(headers)
	err := sm.UnmarshalBinary(aad)
	if err == nil {
		headers = sm.AsMap()
	}
	if err != nil {
		//	if this is plain old binary data, encode it as base64
		headers["aad"] = base64.StdEncoding.EncodeToString(aad)
	}
	return headers
}

func (msg *Message) ToPEM() pem.Block {
	headers := aadToHeaders(msg.AAD)
	if msg.Nonce != nil {
		headers["nonce"] = fmt.Sprintf("%x", msg.Nonce)
	}
	if msg.EphemeralKey != nil {
		headers["eph"] = fmt.Sprintf("%x", msg.EphemeralKey)
	}
	if msg.Signature != nil {
		headers["sig"] = fmt.Sprintf("%x", msg.Signature)
	}
	pemType := headers["pemType"]
	if pemType == "" {
		if msg.IsEncrypted() {
			headers["encrypted"] = "true"
			pemType = "ORACLE ENCRYPTED MESSAGE"
		} else {
			pemType = "ORACLE MESSAGE"
		}
	}
	delete(headers, "pemType")
	block := pem.Block{
		Type:    pemType,
		Bytes:   msg.Body(),
		Headers: headers,
	}
	return block
}

func extractFields(ptr *map[string]string) (encrypted bool, nonce, sig, eph, aad []byte, err error) {
	headers := *ptr

	if headers["encrypted"] == "true" || headers["encrypted"] == "yes" || headers["encrypted"] == "1" {
		encrypted = true
	}
	delete(headers, "encrypted")

	if headers["nonce"] != "" {
		nonce, err = hex.DecodeString(headers["nonce"])
		if err != nil {
			return encrypted, nonce, sig, eph, aad, fmt.Errorf("could not decode nonce. %w", err)
		}
	}
	delete(headers, "nonce")

	if headers["sig"] != "" {
		sig, err = hex.DecodeString(headers["sig"])
		if err != nil {
			return encrypted, nonce, sig, eph, aad, fmt.Errorf("could not decode signature. %w", err)
		}
	}
	delete(headers, "sig")

	if headers["eph"] != "" {
		eph, err = hex.DecodeString(headers["eph"])
		if err != nil {
			return encrypted, nonce, sig, eph, aad, fmt.Errorf("could not decode ephemeral key. %w", err)
		}
	}
	delete(headers, "eph")

	//	if there is exactly one remaining key, and it's called "aad", we're good
	if len(headers) == 1 && headers["aad"] != "" {
		dst := make([]byte, 0, base64.StdEncoding.DecodedLen(len(headers["aad"])))
		_, err = base64.StdEncoding.Decode(dst, []byte(headers["aad"]))
		if err != nil {
			return encrypted, nonce, sig, eph, aad, fmt.Errorf("could not decode aad. %w", err)
		}
		delete(headers, "aad")
		return encrypted, nonce, sig, eph, aad, err
	}

	//	if there is more than zero remaining keys, none of them can be called "aad".
	//	therefore, aad becomes a binary-encoded map of these headers
	if _, exists := headers["aad"]; !exists {
		aad, err = smap.LexicalFrom(headers).MarshalBinary()
		return encrypted, nonce, sig, eph, aad, err
	}

	//	if there are no custom headers at all, there is no AAD, which is fine.
	if len(headers) == 0 {
		return encrypted, nonce, sig, eph, aad, err
	}

	//	It is an error to have an aad header and any other custom header(s).
	err = fmt.Errorf("there was an aad header in addition to %v", headers)
	return encrypted, nonce, sig, eph, aad, err

}

func (msg *Message) reconstituteFromPEM(block *pem.Block) error {
	headers := block.Headers
	headers["pemType"] = block.Type
	encrypted, nonce, sig, eph, aad, err := extractFields(&headers)
	if encrypted {
		msg.CipherText = block.Bytes
	} else {
		msg.PlainText = block.Bytes
	}
	msg.Nonce = nonce
	msg.EphemeralKey = eph
	msg.Signature = sig
	msg.AAD = aad
	return err
}

func (msg *Message) MarshalPEM() ([]byte, error) {
	err := msg.Validate()
	if err != nil {
		return nil, fmt.Errorf("could not marshal. validation failed. %w", err)
	}
	block := msg.ToPEM()
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &block)
	if err != nil {
		//	I don't see how this could happen, but it never hurts to be defensive.
		return nil, fmt.Errorf("could not encode PEM block. %w", err)
	}
	return buf.Bytes(), nil
}

func (msg *Message) UnmarshalPEM(b []byte) error {
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("could not decode PEM block")
	}
	err := msg.reconstituteFromPEM(block)
	if err != nil {
		return err
	}
	return nil
}
