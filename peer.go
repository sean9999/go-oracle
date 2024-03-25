package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"

	"github.com/goombaio/namegenerator"
)

// a Peer is a representation of an entity with a PublicKey, and some optional props.
// It must be fully [de]serializable
type Peer struct {
	EncryptionPublicKey *ecdh.PublicKey   `toml:"ePub"`
	SigningPublicKey    ed25519.PublicKey `toml:"sPub"`
	Nickname            string            `toml:"Nickname"`
}

func PeerFromPublicKeys(ePub *ecdh.PublicKey, sPub ed25519.PublicKey) Peer {
	return Peer{EncryptionPublicKey: ePub, SigningPublicKey: sPub, Nickname: NicknameFromPublicKey(sPub)}
}

func NicknameFromPublicKey(sPub ed25519.PublicKey) string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(sPub)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// a Peer can be hydrated from two public keys
func PeerFromHex(ePubHex, sPubHex string) Peer {
	b, err := hex.DecodeString(ePubHex)
	if err != nil {
		panic("could not create peer from that hex")
	}
	ePub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		panic("could not create peer from that hex")
	}
	s, err := hex.DecodeString(sPubHex)
	if err != nil {
		panic("could not create peer from that hex")
	}
	sPub := ed25519.PublicKey(s)
	return PeerFromPublicKeys(ePub, sPub)
}
