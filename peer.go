package oracle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cbluth/randomart"
	"github.com/goombaio/namegenerator"
)

// 32 bytes for the encryption key, 32 for the signing key
type Peer [64]byte

type PeerConfig struct {
	Nickname  string `json:"nick"`
	PublicKey string `json:"pub"`
}

func (conf PeerConfig) toPeer() (Peer, error) {
	return PeerFromHex([]byte(conf.PublicKey))
}

var NoPeer Peer

func NewPeer(seedSlice []byte) Peer {
	var seed [64]byte
	if len(seedSlice) > 0 {
		//	@todo: should we barf if the slice is not exactly 64 bytes?
		copy(seed[:], seedSlice)
	}
	p := Peer(seed)
	return p
}

// func (p Peer) AsMap() map[string]string {
// 	pHex, _ := p.MarshalHex()
// 	nick := p.Nickname()
// 	m := map[string]string{
// 		"pub":  string(pHex),
// 		"nick": nick,
// 	}
// 	return m
// }

func (p Peer) Config() PeerConfig {
	hex, _ := p.MarshalHex()
	conf := PeerConfig{
		Nickname:  p.Nickname(),
		PublicKey: string(hex),
	}
	return conf
}

func (p Peer) MarshalJSON() ([]byte, error) {
	conf := p.Config()
	return json.MarshalIndent(conf, "", "\t")
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	c := new(PeerConfig)
	json.Unmarshal(data, c)
	return p.UnmarshalHex([]byte(c.PublicKey))
}

// Nickname is a short, memorable, human-readable, semi-unique hash
//
//	It's quite vulnerable to collisions
func (p Peer) Nickname() string {
	s := p.SigningKey()
	publicKeyAsInt64 := binary.BigEndian.Uint64(s)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// ID is a pretty unique hash, appropriate for machines
func (p Peer) ID() [6]byte {
	var id [6]byte
	h := md5.New()
	sum := h.Sum(p[:])
	copy(id[:], sum)
	return id
}

// Randomart produces random art similar to the type you get with SSH keys
//
//	This is a good way for humans to verify or distinguish keys at a glance
func (p Peer) Randomart() string {
	return randomart.RandomArt(p[:], "")
}

func (p Peer) MarshalHex() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(64))
	hex.Encode(dst, p[:])
	return dst, nil
}

func (p *Peer) UnmarshalHex(data []byte) error {
	_, err := hex.Decode(p[:], data)
	return err
}

func (p Peer) MarshalBinary() ([]byte, error) {
	return p[:], nil
}

func (p *Peer) UnmarshalBinary(data []byte) error {
	copy(p[:], data)
	return nil
}

//	TODO: is this too ambiguous?
// func (p Speer) Public() crypto.PublicKey {
// 	s := p.SigningKey()
// 	return crypto.PublicKey(s)
// }

func (p Peer) SigningKey() ed25519.PublicKey {
	bin := p[:32]
	return ed25519.PublicKey(bin)
}

func (p Peer) EncryptionKey() *ecdh.PublicKey {
	bin := p[32:]
	pubKey, err := ecdh.X25519().NewPublicKey(bin)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func (p Peer) Bytes() []byte {
	return p[:]
}

func (p Peer) Equal(x crypto.PublicKey) bool {

	x, isEd := x.(ed25519.PublicKey)
	if isEd {
		return slices.Equal(x.([]byte), p[:32])
	}
	x, isCurvy := x.(*ecdh.PublicKey)
	if isCurvy {
		return slices.Equal(p[32:], x.(*ecdh.PublicKey).Bytes())
	}
	return false
}

func PeerFromHex(hexData []byte) (Peer, error) {
	goodLength := 128
	if len(hexData) != goodLength {
		return NoPeer, fmt.Errorf("bad hex length: %d", len(hexData))
	}
	binData := make([]byte, goodLength)
	hex.Decode(binData, hexData)
	p := NewPeer(binData)
	return p, nil
}

// a XPeer is a representation of an entity with a PublicKey, and some optional props.
// It must be fully [de]serializable
// type XPeer struct {
// 	EncryptionPublicKey *ecdh.PublicKey   `toml:"ePub"`
// 	SigningPublicKey    ed25519.PublicKey `toml:"sPub"`
// 	Nickname            string            `toml:"Nickname"`
// }

// func PeerFromPublicKeys(ePub *ecdh.PublicKey, sPub ed25519.PublicKey) XPeer {
// 	return XPeer{EncryptionPublicKey: ePub, SigningPublicKey: sPub, Nickname: NicknameFromPublicKey(sPub)}
// }

// func NicknameFromPublicKey(sPub ed25519.PublicKey) string {
// 	publicKeyAsInt64 := binary.BigEndian.Uint64(sPub)
// 	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
// 	return gen.Generate()
// }

// // a Peer can be hydrated from two public keys
// func PeerFromHex(ePubHex, sPubHex string) XPeer {
// 	b, err := hex.DecodeString(ePubHex)
// 	if err != nil {
// 		panic("could not create peer from that hex")
// 	}
// 	ePub, err := ecdh.X25519().NewPublicKey(b)
// 	if err != nil {
// 		panic("could not create peer from that hex")
// 	}
// 	s, err := hex.DecodeString(sPubHex)
// 	if err != nil {
// 		panic("could not create peer from that hex")
// 	}
// 	sPub := ed25519.PublicKey(s)
// 	return PeerFromPublicKeys(ePub, sPub)
// }
