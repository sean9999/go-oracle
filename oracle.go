package oracle

import (
	"encoding/binary"
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
var ErrNotFound = errors.New("not found")

type Oracle struct {
	//encryptionPrivateKey *ecdh.PrivateKey
	//EncryptionPublicKey  *ecdh.PublicKey
	//signingPrivateKey    ed25519.PrivateKey
	//SigningPublicKey     ed25519.PublicKey

	Material KeyMatieral

	Version string

	randomness io.Reader
	peers      map[string]Peer
	Handle     io.ReadWriter // usually a file handle
}

func (o *Oracle) PrivateEncryptionKey() *ecdh.PrivateKey {
	b := o.Material.privateEncryption()
	ed := ecdh.X25519()
	privEncKey, err := ed.NewPrivateKey(b)
	if err != nil {
		panic(err)
	}
	return privEncKey
}

func (o *Oracle) PrivateSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(o.Material.privateSigning())
}

func (o *Oracle) PublicEncryptionKey() *ecdh.PublicKey {
	return o.PrivateEncryptionKey().PublicKey()

}

func (o *Oracle) PublicSigningKey() ed25519.PublicKey {
	return ed25519.PublicKey(o.Material.publicSigning())
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
	return o.Material.private()
}

func (o *Oracle) Config() Config {

	h, _ := o.Material.MarshalHex()

	self := SelfConfig{
		o.AsPeer().Config(),
		string(h),
	}
	peersMap := make(map[string]PeerConfig, len(o.peers))
	for nick, p := range o.peers {
		peersMap[nick] = p.Config()
	}
	conf := Config{
		o.Version,
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
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.Material.publicSigning())
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
	return Peer(o.Material.public())
}

func (o *Oracle) Assert() (*PlainText, error) {

	oconf := o.Config()
	assertionMap := make(map[string]string, 5)
	assertionMap["pub"] = oconf.Self.PublicKey
	assertionMap["nick"] = oconf.Self.Nickname
	assertionMap["assertion"] = "I assert that I am me, and this message is unique"
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

func (orc *Oracle) Release() error {
	return orc.Handle.(*os.File).Close()
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

const Version = "v2.0.0"

// a new Oracle needs some initialization to prevent nil-pointer errors.
func (o *Oracle) initialize() {
	o.Version = Version
	if o.peers == nil {
		o.peers = map[string]Peer{}
	}
}
