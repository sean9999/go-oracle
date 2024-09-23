package oracle

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/goombaio/namegenerator"
)

var ErrPeerAlreadyAdded = errors.New("Peer already added")

type Oracle struct {
	encryptionPrivateKey *ecdh.PrivateKey
	EncryptionPublicKey  *ecdh.PublicKey
	signingPrivateKey    ed25519.PrivateKey
	SigningPublicKey     ed25519.PublicKey
	randomness           io.Reader
	peers                map[string]Peer
	Handle               io.ReadWriter // usually a file handle
}

func (o *Oracle) PrivateEncryptionKey() *ecdh.PrivateKey {
	return o.encryptionPrivateKey
}

func (o *Oracle) PrivateSigningKey() ed25519.PrivateKey {
	return o.signingPrivateKey
}

func (o *Oracle) PublicEncryptionKey() *ecdh.PublicKey {
	return o.EncryptionPublicKey
}

func (o *Oracle) PublicSigningKey() ed25519.PublicKey {
	return o.SigningPublicKey
}

// Deterministic sets Oracle to deterministic mode.
// Good for testing.
// Bad for privacy.
func (o *Oracle) Deterministic() {
	o.randomness = &BunchOfZeros{}
}

func (o *Oracle) Randomness() io.Reader {
	return o.randomness
}

func (o *Oracle) Bytes() []byte {
	bin := make([]byte, 64+32)
	copy(bin[:32], o.PrivateEncryptionKey().Bytes())
	p := o.AsPeer()
	pub, _ := p.MarshalBinary()
	copy(bin[32:], pub)
	return bin
}

func (o *Oracle) Config() Config {
	self := SelfConfig{
		o.AsPeer().Config(),
		hex.EncodeToString(o.PrivateEncryptionKey().Bytes()),
	}
	peersMap := make(map[string]PeerConfig, len(o.peers))
	for nick, p := range o.peers {
		peersMap[nick] = p.Config()
	}
	conf := Config{
		self,
		peersMap,
	}
	return conf
}

// func (o *Oracle) AsMap() map[string]string {
// 	m := o.AsPeer().AsMap()
// 	m["priv"] = hex.EncodeToString(o.PrivateEncryptionKey().Bytes())
// 	return m
// }

// an easy way to uniquely identify a Peer. Nickname is derived from PublicKey
// collisions are technically possible
// TODO: make nicknames less succeptable to collisions, by making them longer
func (o *Oracle) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.SigningPublicKey)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// Make an Oracle aware of a Peer.
// so it can encrypt messages or validate signatures using it's nickname.
// If a peer is added, that implies we trust it (ie: we have validated it's signature).
func (o *Oracle) AddPeer(p Peer) error {

	if p.Equal(NoPeer) {
		return errors.New("this is not a peer")
	}

	_, keyExists := o.peers[p.Nickname()]
	o.peers[p.Nickname()] = p
	//	persist
	if !keyExists {
		return o.Save()
	}
	return ErrPeerAlreadyAdded
}

var ErrNotFound = errors.New("not found")

// get a Peer from its Nickname
func (o *Oracle) Peer(nick string) (Peer, error) {
	p, ok := o.peers[nick]
	if ok {
		return p, nil
	} else {
		return NoPeer, fmt.Errorf("%w: no such peer %q", ErrNotFound, nick)
	}
}

func (o *Oracle) Peers() map[string]Peer {
	return o.peers
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *Oracle) AsPeer() Peer {
	pub := [64]byte{}
	sig := o.SigningPublicKey
	enc := o.EncryptionPublicKey.Bytes()
	copy(pub[:32], sig)
	copy(pub[32:], enc)
	p := NewPeer(pub[:])
	return p
}

func (o *Oracle) Assert() (*PlainText, error) {

	oconf := o.Config()
	assertionMap := make(map[string]string, 5)
	assertionMap["pub"] = oconf.Self.PublicKey
	assertionMap["nick"] = oconf.Self.Nickname
	assertionMap["assertion"] = "I assert that this message was signed by me, that it is unique by virtue of a timestamp and a nonce, and that my public key is included in this message."
	assertionMap["now"] = fmt.Sprintf("%d", time.Now().UnixNano())

	j, err := json.Marshal(assertionMap)
	if err != nil {
		return nil, err
	}
	pt := o.Compose("assertion", j)
	pt.Headers["pubkey"] = assertionMap["pub"]
	err = pt.Sign(o.randomness, o.PrivateSigningKey())
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// create a new Oracle with new key-pairs.
func New(rand io.Reader) *Oracle {
	orc := &Oracle{
		randomness: rand,
	}
	orc.initialize()
	err := orc.GenerateKeys(rand)
	if err != nil {
		panic(err)
	}
	return orc
}

// load an Oracle from a file or some other [io.Reader]
func From(r io.ReadWriter) (*Oracle, error) {
	//defer r.Close()
	orc := &Oracle{
		randomness: rand.Reader,
		Handle:     r,
	}
	orc.initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return orc, nil
}

func FromFile(path string) (*Oracle, error) {
	configFile, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return From(configFile)
}

// a new Oracle needs some initialization to prevent nil-pointer errors.
func (o *Oracle) initialize() {
	if o.peers == nil {
		o.peers = map[string]Peer{}
	}
}
