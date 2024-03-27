package oracle

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/goombaio/namegenerator"
)

type Peer interface {
	crypto.PublicKey
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	json.Marshaler
	json.Unmarshaler
	//toml.Marshaler
	//toml.Unmarshaler
	MarshalHex() ([]byte, error)
	UnmarshalHex(data []byte) error
	Bytes() []byte
	Public() crypto.PublicKey // returns signing key
	SigningKey() ed25519.PublicKey
	EncryptionKey() *ecdh.PublicKey
	Nickname() string
	AsMap() map[string]string
}

// 32 bytes for the encryption key, 32 for the signing key
type peer [64]byte

func NewPeer(seed []byte) Peer {
	p := peer(seed)
	return &p
}

func (p *peer) AsMap() map[string]string {
	pHex, _ := p.MarshalHex()
	nick := p.Nickname()
	m := map[string]string{
		"pub":  string(pHex),
		"nick": nick,
	}
	return m
}

func (p *peer) MarshalJSON() ([]byte, error) {
	m := p.AsMap()
	return json.MarshalIndent(m, "", "\t")
}

func (p *peer) UnmarshalJSON(data []byte) error {
	var m map[string]string
	json.Unmarshal(data, &m)
	pHex := m["pub"]
	return p.UnmarshalHex([]byte(pHex))
}

func (p *peer) Nickname() string {
	s := p.SigningKey()
	publicKeyAsInt64 := binary.BigEndian.Uint64(s)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

func (p *peer) MarshalHex() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(64))
	hex.Encode(dst, p[:])
	return dst, nil
}

func (p *peer) UnmarshalHex(data []byte) error {
	_, err := hex.Decode(p[:], data)
	return err
}

func (p *peer) MarshalBinary() ([]byte, error) {
	return p[:], nil
}

func (p *peer) UnmarshalBinary(data []byte) error {
	copy(p[:], data)
	return nil
}

func (p *peer) Public() crypto.PublicKey {
	s := p.SigningKey()
	return crypto.PublicKey(s)
}

func (p *peer) SigningKey() ed25519.PublicKey {
	bin := p[:32]
	return ed25519.PublicKey(bin)
}

func (p *peer) EncryptionKey() *ecdh.PublicKey {
	bin := p[32:]
	pubKey, err := ecdh.X25519().NewPublicKey(bin)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func (p *peer) Bytes() []byte {
	return p[:]
}

func (p *peer) Equal(x crypto.PublicKey) bool {

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
	//	@todo: barf if len(hexData) is wrong
	binData := make([]byte, hex.DecodedLen(len(hexData)))
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
