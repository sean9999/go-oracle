package delphi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair [2]Key

var ZeroKeyPair KeyPair

func (kp KeyPair) MarshalJSON() ([]byte, error) {
	str := kp.String()
	return json.Marshal(str)
}

func (kp *KeyPair) UnmarshalJSON(data []byte) error {
	var hexString string
	err := json.Unmarshal(data, &hexString)
	if err != nil {
		return err
	}
	bin, err := hex.DecodeString(hexString)
	if err != nil {
		return err
	}
	_, err = kp.Write(bin)
	return err
}

func (kp KeyPair) Bytes() []byte {
	///kp.MustBeValid()
	return append(kp[0].Bytes(), kp[1].Bytes()...)
}

func (kp KeyPair) MustBeValid() {
	kp[0].MustBeValid()
	kp[1].MustBeValid()
}

func (kp *KeyPair) Write(p []byte) (int, error) {

	const keySize = subKeySize * 2

	if len(p) < keySize*2 {
		return 0, io.ErrShortWrite
	}
	_, err := kp[0].Write(p[:keySize])
	if err != nil {
		return 0, err
	}
	_, err = kp[1].Write(p[keySize:])
	if err != nil {
		return 0, err
	}
	return keySize * 2, nil
}

// NewKeyPair generates valid ed25519 and X25519 keys
func NewKeyPair(randy io.Reader) KeyPair {

	/**
	 * Layout:
	 *	1st 32 bytes:	public	encryption key
	 *	2nd 32 bytes:	public	signing	key
	 *	3rd 32 bytes:	private encryption key
	 *	4th 32 bytes:	private signing key
	 **/

	//	if randy is nil, simply return a zero KeyPair
	//	this is useful for when you want to unmarshal.
	//	In that case, there is no need for randomness and no need to go through the expense of creating keys
	if randy == nil {
		return ZeroKeyPair
	}

	//	encryption keys
	ed := ecdh.X25519()
	encryptionPriv, err := ed.GenerateKey(randy)
	if err != nil {
		panic(err)
	}
	encryptionPub := encryptionPriv.PublicKey()

	//	signing keys
	signPub, signPriv, err := ed25519.GenerateKey(randy)
	if err != nil {
		panic(err)
	}

	priv := PrivateKey{
		SubKey(encryptionPriv.Bytes()),
		SubKey(signPriv[:subKeySize]),
	}

	pub := PublicKey{
		SubKey(encryptionPub.Bytes()),
		SubKey(signPub),
	}

	kp := KeyPair{
		Key(pub),
		Key(priv),
	}

	return kp
}

func (kp KeyPair) PublicKey() PublicKey {
	return PublicKey(kp[0])
}

func (kp KeyPair) PrivateKey() PrivateKey {
	return PrivateKey(kp[1])
}

// A PrivateSigningKey contains both private and public key material. That's just how ed25519 works
func (kp KeyPair) PrivateSigningKey() Key {
	bin1 := kp.PrivateKey().Signing().Bytes()
	bin2 := kp.PublicKey().Signing().Bytes()
	k := new(Key)
	_, _ = k.Write(append(bin1, bin2...))
	return *k
}

// String is a hex representation of the key.
func (kp KeyPair) String() string {
	kp.MustBeValid()
	return hex.EncodeToString(kp.Bytes())
}

// Sign signs a digest. This satisfies crypto.Signer.
func (kp KeyPair) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	privKey := ed25519.PrivateKey(kp.PrivateSigningKey().Bytes())
	sig := ed25519.Sign(privKey, digest)
	return sig, nil
}

func (kp KeyPair) Verify(pubKey crypto.PublicKey, digest []byte, signature []byte) bool {
	pubBytes, err := asBytes(pubKey)
	if err != nil {
		return false
	}
	return ed25519.Verify(pubBytes, digest, signature)
}

var _ crypto.Signer = KeyPair{}

func (kp KeyPair) Public() crypto.PublicKey {
	return kp.PublicKey()
}

// extractSharedSecret calculates a shared secret using a shared ephemeral public key, and the principal's own key material.
// This is possible because the ephemeral key was generated using the recipient's public key.
func (kp KeyPair) extractSharedSecret(ephemeralPubKey []byte) ([]byte, error) {
	recipientPrivKey := kp.PrivateKey().Encryption().Bytes()
	recipientPubKey := kp.PublicKey().Encryption().Bytes()
	sharedScalar, err := curve25519.X25519(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, len(ephemeralPubKey)+len(recipientPubKey))
	copy(salt[:len(ephemeralPubKey)], ephemeralPubKey)
	copy(salt[len(ephemeralPubKey):], recipientPubKey)

	h := hkdf.New(sha256.New, sharedScalar, salt, []byte(GlobalSalt))
	sharedSecret := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecret); err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func (kp KeyPair) Decrypt(msg, eph, nonce, aad []byte) (plaintext []byte, err error) {
	sharedSec, err := kp.extractSharedSecret(eph)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt. %w", err)
	}
	cipher, err := chacha20poly1305.New(sharedSec)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt. %w", err)
	}
	plaintext, err = cipher.Open(nil, nonce, msg, aad)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt. %w", err)
	}
	return plaintext, nil
}

func (kp KeyPair) Seal(sec []byte, plainText []byte, nonce []byte, aad []byte) ([]byte, error) {
	sealer, err := chacha20poly1305.New(sec)
	if err != nil {
		return nil, err
	}
	return sealer.Seal(nil, nonce, plainText, aad), nil
}

// asBytes takes a thing and tries its best to return it as a byte-slice.
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
	marshaler, ok := thing.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("not a binary marshaler")
	}
	return marshaler.MarshalBinary()
}

func (kp KeyPair) GenerateSharedSecret(randomness io.Reader, pubKey PublicKey) (sharedSecret []byte, ephemeralPubKey []byte, err error) {

	counterPartyPubKey := pubKey.Encryption().Bytes()

	//	generate an ephemeral private key
	ephemeralPrivKey := make([]byte, curve25519.ScalarSize)
	if _, err := randomness.Read(ephemeralPrivKey); err != nil {
		return nil, nil, err
	}

	//	extract the public key from it
	ephemeralPubKey, err = curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	//	derive a key from the counterparty's public key and ephemeral private key
	secretScalar, err := curve25519.X25519(ephemeralPrivKey, counterPartyPubKey)
	if err != nil {
		return nil, nil, err
	}

	//	our salt is the ephemeral public key plus the counterparty's public key
	salt := make([]byte, len(ephemeralPubKey)+len(counterPartyPubKey))
	copy(salt[:len(ephemeralPubKey)], ephemeralPubKey)
	copy(salt[len(ephemeralPubKey):], counterPartyPubKey)

	//	derive a symmetric key. This is our shared secret
	h := hkdf.New(sha256.New, secretScalar, salt, []byte(GlobalSalt))
	sharedSecret = make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, sharedSecret); err != nil {
		return nil, nil, err
	}

	//	ephemeralPublicKey will be sent over the wire.
	//	sharedSecret will not. That's what we use to encrypt our message
	//	Counterparty will be able to calculate it using their private key and ephemeral public key.
	return sharedSecret, ephemeralPubKey, nil
}
