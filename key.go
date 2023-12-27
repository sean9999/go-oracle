package oracle

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	util "git.mills.io/prologic/cryptutils/public"
	"github.com/goombaio/namegenerator"
)

// the derived nickname from the zero-key is always this
const ZERO_NICKNAME = "zero-entity"

// these values should not occur naturally. If they do, you have a bug.
var NilPrivateKey = PrivateKey{}
var NilPublicKey = PublicKey{}
var ZeroPrivateKey = NewZeroPrivateKey()

// a PrivateKey implements [essence.PrivateKey] and embeds key material from [util.PrivateKey]
type PrivateKey struct {
	material *util.PrivateKey
}

// a PublicKey implements [essence.PublicKey] and embeds [util.PublicKey]
type PublicKey struct {
	material *util.PublicKey
}

func (key PublicKey) AsBinary() []byte {
	bin, _ := util.MarshalPublic(key.material)
	return bin
}

func (key PublicKey) AsHex() string {
	bin := key.AsBinary()
	txt := hex.EncodeToString(bin)
	return txt
}

func (key PrivateKey) AsBinary() []byte {
	bin, _ := util.MarshalPrivate(key.material)
	return bin
}

func (key PrivateKey) AsHex() string {
	bin := key.AsBinary()
	txt := hex.EncodeToString(bin)
	return txt
}

// returns the corresponding PublicKey to a PrivateKey
func (priv PrivateKey) Public() PublicKey {
	var pub PublicKey
	if priv.material != nil {
		pub.material = priv.material.PublicKey
	}
	return pub
}

// returns true of the PrivateKey is valid.
func (key PrivateKey) Valid() bool {
	return key.material.Valid()
}

// exposes [util.PrivateKey] to enable primitive crypto operations
func (key PrivateKey) Material() *util.PrivateKey {
	return key.material
}

// exposes [util.PublicKey] to enable primitive crypto operations
func (key PublicKey) Material() *util.PublicKey {
	return key.material
}

func PublicKeyFromBytes(data []byte) (PublicKey, error) {
	innerKey, err := util.UnmarshalPublic(data)
	pub := PublicKey{innerKey}
	return pub, err
}

func PublicKeyFromHex(txt string) (PublicKey, error) {
	b, err := hex.DecodeString(txt)
	if err == nil {
		return PublicKeyFromBytes(b)
	}
	return PublicKey{}, errors.New("could not decode hex")
}

func PrivateKeyFromBytes(data []byte) (PrivateKey, error) {
	innerKey, err := util.UnmarshalPrivate(data)
	priv := PrivateKey{innerKey}
	return priv, err
}

func PrivateKeyFromHex(txt string) (PrivateKey, error) {
	b, err := hex.DecodeString(txt)
	if err == nil {
		return PrivateKeyFromBytes(b)
	}
	return PrivateKey{}, errors.New("could not decode hex")
}

//	deterministic nicknames. We convert the public key to an int64, and set that value to
//
// the seed of the random number generator
func NicknameFromPublicKey(pub PublicKey) string {
	b := pub.Material().V[:]
	num := binary.BigEndian.Uint64(b)
	nickname := ZERO_NICKNAME
	if num != 0 {
		nameGenerator := namegenerator.NewNameGenerator(int64(num))
		nickname = nameGenerator.Generate()
	}
	return nickname
}

func NewPrivateKey() PrivateKey {
	mat, _ := util.GenerateKey()
	priv := PrivateKey{mat}
	return priv
}

func NewZeroPrivateKey() PrivateKey {
	z32 := [32]byte{}
	z64 := [64]byte{}
	underlyingPub := util.PublicKey{
		E: &z32,
		V: &z32,
	}
	underlyingPriv := util.PrivateKey{
		D:         &z32,
		S:         &z64,
		PublicKey: &underlyingPub,
	}
	k := PrivateKey{&underlyingPriv}
	return k
}
