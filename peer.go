package oracle

import (
	"encoding/hex"
	"errors"

	util "git.mills.io/prologic/cryptutils/public"
	"github.com/sean9999/go-oracle/essence"
)

// a Peer is a representation of an entity with a PublicKey.
// It implements [essence.Peer]
type Peer map[string]string

func (p Peer) Public() essence.PublicKey {
	pubHex := p["PublicKey"]
	b, _ := hex.DecodeString(pubHex)
	k, _ := util.UnmarshalPublic(b)
	return PublicKey{k}
}

func (p Peer) Nickname() string {
	return p["Nickname"]
}

// a Peer can be hydrated from a public key
func PeerFromHex(hex string) essence.Peer {
	pub, _ := PublicKeyFromHex(hex)
	p := Peer{
		"Nickname":  NicknameFromPublicKey(pub),
		"PublicKey": hex,
	}
	return p
}

// a Peer can have arbitrary key-value pairs, called Annotations.
func (p Peer) Annotations() map[string]string {
	m := map[string]string{}
	for k, v := range p {
		if k != "PublicKey" {
			m[k] = v
		}
	}
	return m
}

// a Peer is valid if it has a PublicKey, and that PublicKey is valid.
func (p Peer) Validate() error {
	pubHex, exists := p["PublicKey"]
	if !exists {
		return errors.New("Peer does not have a public key")
	}
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return errors.New("public key was not valid hex")
	}
	k, err := util.UnmarshalPublic(b)
	if err != nil {
		return errors.New("public key is not a valid ed25519 key")
	}
	nickname, exists := p["Nickname"]
	if exists {
		want := NicknameFromPublicKey(PublicKey{k})
		if want != nickname {
			return errors.New("nickname and public key don't match")
		}
	}
	return nil
}
