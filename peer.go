package oracle

import (
	"crypto"
	"encoding/binary"
	"encoding/hex"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/goombaio/namegenerator"
	"github.com/sean9999/go-oracle/essence"
)

// a Peer is a representation of an entity with a PublicKey, and some optional props.
// It must be fully [de]serializable.
// It implements [essence.Peer]
type Peer struct {
	PublicKey x25519.Key `toml:"PublicKey"`
	Nickname  string     `toml:"Nickname"`
}

// func (a *address) UnmarshalText(text []byte) error {
// 	var err error
// 	a.Address, err = mail.ParseAddress(string(text))
// 	return err
// }

func (p Peer) Public() crypto.PublicKey {
	return p.PublicKey
}

func (p Peer) Nick() string {
	return p.Nickname
}

func NicknameFromPublicKey(pub x25519.Key) string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(pub[:])
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// a Peer can be hydrated from a public key
func PeerFromHex(x string) essence.Peer {
	b, _ := hex.DecodeString(x)
	pubKey := x25519.Key(b)
	p := Peer{PublicKey: pubKey, Nickname: NicknameFromPublicKey(pubKey)}
	return p
}
