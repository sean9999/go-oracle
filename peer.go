package oracle

import (
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"

	"github.com/goombaio/namegenerator"
)

// a Peer is a representation of an entity with a PublicKey, and some optional props.
// It must be fully [de]serializable.
// It implements [essence.Peer]
type Peer struct {
	PublicKey *ecdh.PublicKey `toml:"PublicKey"`
	Nickname  string          `toml:"Nickname"`
}

func PeerFromPublicKey(pubKey *ecdh.PublicKey) Peer {
	return Peer{PublicKey: pubKey, Nickname: NicknameFromPublicKey(pubKey)}
}

func NicknameFromPublicKey(pub *ecdh.PublicKey) string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(pub.Bytes())
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// a Peer can be hydrated from a public key
func PeerFromHex(x string) Peer {
	b, _ := hex.DecodeString(x)
	pubKey, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		panic("could not create peer from that hex")
	}
	return PeerFromPublicKey(pubKey)
}
