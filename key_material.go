package oracle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const PubEncryptKeySize = 32  // first 32 bytes of [ed25519.PrivateKey]
const PrivEncryptKeySize = 32 // last 32 bytes of [ed25519.PrivateKey]
const PubSigningKeySize = 32  // [ecdh.PublicKey]
const PrivSigningKeySize = 32 // [ecdh.PrivateKey]

const KeyMatieralSize = PrivEncryptKeySize + PubEncryptKeySize + PrivSigningKeySize + PubSigningKeySize

type KeyMatieral [KeyMatieralSize]byte

/**

The ed25519 spec embeds the public key in the private key, but for purposes
of storing the bits, we make a distinction.

|      32      |      32      |     32      |     32     |
---------------------------------------------------------
|    slot 1   |    slot 2    |     slot 3  |   slot 4   |
| pub encrypt | priv encrypt |  pub sign   | priv sign  |
|   ed25519 private key     |
**/

const slot1 = 0                          // public encryption
const slot2 = slot1 + PubEncryptKeySize  // private encryption
const slot3 = slot2 + PrivEncryptKeySize // public signing
const slot4 = slot3 + PubSigningKeySize  // private signing
const slotEnd = KeyMatieralSize

func (_ KeyMatieral) Generate(rand io.Reader) KeyMatieral {

	var km KeyMatieral

	//	private encrpytion key
	privEnc := make([]byte, PrivEncryptKeySize)
	io.ReadFull(rand, privEnc)
	copy(km[slot2:slot3], privEnc)

	//	private signing key
	privSignBytes := make([]byte, PrivSigningKeySize)
	io.ReadFull(rand, privSignBytes)
	copy(km[slot4:], privSignBytes)

	km.derive()
	return km
}

func (km *KeyMatieral) derive() error {
	//	public signing key
	privSign := km.privateSigning()
	pubSignBytes := ed25519.NewKeyFromSeed(privSign).Public().(ed25519.PublicKey)
	copy(km[slot3:slot4], pubSignBytes)

	// public encryption
	privEnc := km.privateEncryption()
	ed := ecdh.X25519()
	privEncKey, err := ed.NewPrivateKey(privEnc)
	if err != nil {
		return err
	}
	pubEncKey := privEncKey.PublicKey()
	copy(km[slot1:slot2], pubEncKey.Bytes()[:])
	return nil
}

// MarshalHex only exports private key material
//
//	the rest can be derived
func (km KeyMatieral) MarshalHex() ([]byte, error) {
	bin, err := km.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h := make([]byte, len(bin)*2)
	hex.Encode(h, bin)
	return h, nil
}

func (km *KeyMatieral) UnmarshalHex(h []byte) error {
	privateBytes := make([]byte, PrivEncryptKeySize+PrivEncryptKeySize, len(h))
	_, err := hex.Decode(privateBytes, h)
	if err != nil {
		return err
	}
	return km.UnmarshalBinary(privateBytes)
}

// only private key material is needed. The rest can be derived
func (km KeyMatieral) MarshalBinary() ([]byte, error) {
	return km.private(), nil
}

// only private key material is needed. The rest is derived
func (km *KeyMatieral) UnmarshalBinary(p []byte) error {
	if len(p) != PrivEncryptKeySize+PrivSigningKeySize {
		return errors.New("bad length")
	}
	km.setPrivate(p)
	km.derive()
	return nil
}

func (km KeyMatieral) private() []byte {
	return append(km.privateEncryption(), km.privateSigning()...)
}

func (km *KeyMatieral) setPrivate(p []byte) error {
	if len(p) != PrivEncryptKeySize+PrivSigningKeySize {
		return errors.New("wrong size")
	}
	i := copy(km[slot2:slot3], p[:PrivEncryptKeySize])
	if i != PrivEncryptKeySize {
		return errors.New("wrong size for priv enc")
	}
	i = copy(km[slot4:], p[PrivEncryptKeySize:])
	if i != PrivSigningKeySize {
		return errors.New("wrong size for priv sig")
	}
	return nil
}

func (km *KeyMatieral) setPublic(p []byte) error {
	if len(p) != PubEncryptKeySize+PubSigningKeySize {
		return errors.New("wrong size")
	}
	bytesWritten := copy(km[:slot2], p[:PubEncryptKeySize]) + copy(km[slot3:slot4], p[PubEncryptKeySize:])
	if bytesWritten != PubEncryptKeySize+PubSigningKeySize {
		return errors.New("something crazy happened")
	}
	return nil
}

func (km KeyMatieral) public() []byte {
	return append(km.publicEncryption(), km.publicSigning()...)
}

func (km KeyMatieral) privateEncryption() []byte {
	return km[slot2:slot3]
}

// func (km KeyMatieral) privateEncryptionKey() *ecdh.PrivateKey {
// 	b := km.privateEncryptionBytes()
// 	ed := ecdh.X25519()
// 	privEncKey, err := ed.NewPrivateKey(b)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return privEncKey
// }

func (km KeyMatieral) privateSigning() []byte {
	return km[slot4:]
}

// func (km KeyMatieral) privateSigningKey() ed25519.PrivateKey {
// 	return ed25519.NewKeyFromSeed(km.privateSigningBytes())
// }

func (km KeyMatieral) publicSigning() []byte {
	return km[slot3:slot4]
}

func (km KeyMatieral) publicEncryption() []byte {
	return km[slot1:slot2]
}

// func (km KeyMatieral) PublicSigningKey() ed25519.PublicKey {
// 	return ed25519.PublicKey(km.publicSigningBytes())
// }

// func (km KeyMatieral) PublicEncryptionKey() *ecdh.PublicKey {
// 	return km.privateEncryptionKey().PublicKey()
// }

func (km KeyMatieral) validateSigning() error {

	msg := []byte("hello work.d.")

	//	private key includes public key

	//b := append(km.publicSigning(), km.privateSigning()...)
	b := km.privateSigning()
	privKey := ed25519.NewKeyFromSeed(b)
	sig, err := privKey.Sign(nil, msg, &ed25519.Options{})
	if err != nil {
		return err
	}

	pubkey := ed25519.PublicKey(km.publicSigning())

	ok := ed25519.Verify(pubkey, msg, sig)
	if !ok {
		return errors.New("verification failed")
	}
	return nil
}

var ZeroKey [32]byte

func (km KeyMatieral) validateNoZeros() error {
	markers := []int{slot1, slot2, slot3, slot4}

	for _, marker := range markers {
		if !bytes.Equal(km[marker:marker+32], ZeroKey[:]) {
			return fmt.Errorf("zero key found at index %d", marker)
		}
	}
	return nil
}

func (km KeyMatieral) validateEncryption(rand io.Reader) error {
	priv := km.privateEncryption()
	pub := km.publicEncryption()

	ed := ecdh.X25519()
	privEncKey, err := ed.NewPrivateKey(priv)
	pubKey := privEncKey.PublicKey()

	plain := []byte("helo world")

	share1, ephKey, err := generateSharedSecret(pubKey, rand)

	if ephKey == nil {
		return errors.New("ephKey nil")
	}

	share2, err := extractSharedSecret(ephKey, priv, pub)

	if !bytes.Equal(share1, share2) {
		return errors.New("generated and extrated secreat were different")
	}

	ciph, err := encrypt(share1, plain)
	if err != nil {
		return err
	}

	p, err := decrypt(share1, ciph)
	if err != nil {
		return err
	}
	if bytes.Equal(plain, p) {
		return nil
	}
	return errors.New("not equal")
}

func (km KeyMatieral) validateEncPairs() error {
	b := km.privateEncryption()
	ed := ecdh.X25519()
	priv1, err := ed.NewPrivateKey(b)
	if err != nil {
		return err
	}
	pub1, err := ed.NewPublicKey(km.publicEncryption())
	if err != nil {
		return err
	}
	pub2 := priv1.PublicKey()
	eq := pub1.Equal(pub2)
	if !eq {
		return errors.New("encryption keys don't match")
	}
	return nil
}

func (km KeyMatieral) validateSignPairs() error {
	b := km.privateSigning()
	privKey1 := ed25519.NewKeyFromSeed(b)
	pubKey1 := ed25519.PublicKey(km.publicSigning())
	pubkey2 := privKey1.Public()
	if !pubKey1.Equal(pubkey2) {
		return errors.New("keys don't match")
	}
	return nil
}

func (km KeyMatieral) validate(rand io.Reader) error {
	if err := km.validateEncryption(rand); err != nil {
		return err
	}
	if err := km.validateNoZeros(); err != nil {
		return err
	}
	if err := km.validateSigning(); err != nil {
		return err
	}
	if err := km.validateEncPairs(); err != nil {
		return err
	}
	if err := km.validateSignPairs(); err != nil {
		return err
	}
	return nil
}
