package oracle

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/goombaio/namegenerator"
)

//	agedMorning.Compose(POET, []byte(SAYING), greenBrook.AsPeer())

// type Oracle interface {
// 	PrivateSigningKey() ed25519.PrivateKey
// 	PublicSigningKey() ed25519.PublicKey
// 	PrivateEncryptionKey() *ecdh.PrivateKey
// 	PublicEncryptionKey() *ecdh.PublicKey
// 	Compose(string, []byte) *PlainText
// 	Sign(*PlainText) error
// 	Verify(*PlainText, Peer) bool
// 	Encrypt(*PlainText, Peer) (*CipherText, error)
// 	Decrypt(*CipherText) (*PlainText, error)
// 	Export(io.Writer) error
// 	//Import(Config) error
// 	Randomness() io.Reader
// 	AddPeer(Peer) error
// 	AsPeer() Peer
// 	Peer(string) (Peer, error)
// 	Peers() map[string]Peer
// }

type Oracle struct {
	encryptionPrivateKey *ecdh.PrivateKey
	EncryptionPublicKey  *ecdh.PublicKey
	signingPrivateKey    ed25519.PrivateKey
	SigningPublicKey     ed25519.PublicKey
	randomness           io.Reader
	peers                map[string]Peer
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

func (o *Oracle) AsMap() map[string]string {
	m := o.AsPeer().AsMap()
	m["priv"] = hex.EncodeToString(o.PrivateEncryptionKey().Bytes())
	return m
}

// an easy way to uniquely identify a Peer. Nickname is derived from PublicKey
// collisions are technically possible
func (o *Oracle) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.SigningPublicKey)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// Make an Oracle aware of a Peer, so it can encrypt messages or validate signatures
func (o *Oracle) AddPeer(p Peer) error {
	o.peers[p.Nickname()] = p
	return nil
}

// get a Peer from its Nickname
func (o *Oracle) Peer(nick string) (Peer, error) {
	p, ok := o.peers[nick]
	if ok {
		return p, nil
	} else {
		return nil, errors.New("no such Peer")
	}
}

func (o *Oracle) Peers() map[string]Peer {
	return o.peers
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *Oracle) AsPeer() *peer {
	pub := [64]byte{}
	sig := o.SigningPublicKey
	enc := o.EncryptionPublicKey.Bytes()
	copy(pub[:32], sig)
	copy(pub[32:], enc)
	p := NewPeer(pub[:])
	return p
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

// load an Oracle from a file or other io.Reader
func From(r io.Reader) (*Oracle, error) {
	//defer r.Close()
	orc := &Oracle{
		randomness: rand.Reader,
	}
	orc.initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return orc, nil
}

func FromFile(path string) (*Oracle, error) {
	configFile, err := os.Open(path)
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
