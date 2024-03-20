package oracle

import (
	"crypto"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"

	"github.com/goombaio/namegenerator"
	"github.com/sean9999/go-oracle/essence"
)

// a Peer is a representation of an entity with a PublicKey, and some optional props.
// It must be fully [de]serializable.
// It implements [essence.Peer]
type Peer struct {
	PublicKey *ecdh.PublicKey `toml:"PublicKey"`
	Nickname  string          `toml:"Nickname"`
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

func NicknameFromPublicKey(pub *ecdh.PublicKey) string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(pub.Bytes())
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// a Peer can be hydrated from a public key
func PeerFromHex(x string) essence.Peer {
	b, _ := hex.DecodeString(x)
	pubKey, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		panic("could not create peer from that hex")
	}
	//p := Peer{PublicKey: pubKey, Nickname: NicknameFromPublicKey(pubKey)}
	//return p
	return PeerFromKey(pubKey)
}

func PeerFromKey(pubKey *ecdh.PublicKey) essence.Peer {
	return Peer{PublicKey: pubKey, Nickname: NicknameFromPublicKey(pubKey)}
}
