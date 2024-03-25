package oracle

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/goombaio/namegenerator"
)

type Principal interface {
	PrivateSigningKey() ed25519.PrivateKey
	PublicSigningKey() ed25519.PublicKey
	PrivateEncryptionKey() *ecdh.PrivateKey
	PublicEncryptionKey() *ecdh.PublicKey
	Sign(Message) error
	Verify(Message, ed25519.PublicKey) bool
	Encrypt(Message, ecdh.PublicKey) Message
	Decrypt(Message) (Message, error)
	Export(io.Writer) error
	Import(Config) error
	Randomness() io.Reader
}

type Oracle struct {
	EncryptionPrivateKey *ecdh.PrivateKey
	EncryptionPublicKey  *ecdh.PublicKey

	SigningPrivateKey ed25519.PrivateKey
	SigningPublicKey  ed25519.PublicKey

	randomness io.Reader

	Peers map[string]Peer
}

// an easy way to uniquely identify a Peer. Nickname is dereived from PublicKey
func (o *Oracle) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.SigningPublicKey)
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// Make an Oracle aware of a Peer, so it can encrypt messages or validate signatures
func (o *Oracle) AddPeer(p Peer) error {
	o.Peers[p.Nickname] = p
	return nil
}

// get a Peer from its Nickname
func (o *Oracle) Peer(nick string) (*Peer, error) {
	p, ok := o.Peers[nick]
	if ok {
		return &p, nil
	} else {
		return nil, errors.New("no such Peer")
	}
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *Oracle) AsPeer() *Peer {
	p := Peer{
		SigningPublicKey:    o.SigningPublicKey,
		EncryptionPublicKey: o.EncryptionPublicKey,
		Nickname:            o.Nickname(),
	}
	return &p
}

// create a new Oracle with new key-pairs.
func New(rand io.Reader) *Oracle {
	orc := Oracle{
		randomness: rand,
	}
	orc.initialize()
	err := orc.GenerateKeys(rand)
	if err != nil {
		panic(err)
	}
	return &orc
}

// load an Oracle from a file or other io.Reader
func From(r io.Reader) (*Oracle, error) {
	//defer r.Close()
	orc := Oracle{
		randomness: rand.Reader,
	}
	orc.initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return &orc, nil
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
	if o.Peers == nil {
		o.Peers = map[string]Peer{}
	}
}
