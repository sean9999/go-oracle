package oracle

import (
	"encoding/hex"
	"errors"

	util "git.mills.io/prologic/cryptutils/public"
	"github.com/sean9999/go-oracle/essence"
)

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

func PeerFromHex(hex string) essence.Peer {
	pub, _ := PublicKeyFromHex(hex)
	p := Peer{
		"Nickname":  NicknameFromPublicKey(pub),
		"PublicKey": hex,
	}
	return p
}

func (p Peer) Annotations() map[string]string {
	m := map[string]string{}
	for k, v := range p {
		if k != "PublicKey" {
			m[k] = v
		}
	}
	return m
}

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
