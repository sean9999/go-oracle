package gork

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	"github.com/sean9999/go-delphi"
	stablemap "github.com/sean9999/go-stable-map"
	"github.com/sean9999/pear"
	"github.com/spf13/afero"
)

// KV is a key-value store whose keys are ordered, offering deterministic serialization
type KV = stablemap.StableMap[string, string]

func NewKV() *KV {
	return stablemap.New[string, string]()
}

// a Principal is a public/private key-pair with some properties, and knowlege of [Peer]s
type Principal struct {
	delphi.Principal `msgpack:"priv" json:"priv" yaml:"priv"`
	Props            *KV                 `msgpack:"props" json:"props" yaml:"props"`
	Peers            map[delphi.Key]Peer `msgpack:"peers" json:"peers" yaml:"peers"`
	randomness       io.Reader           `msgpack:"-" json:"-" yaml:"-"`
	Config           *Config             `msgpack:"-" json:"-" yaml:"-"`
}

func (g Principal) ensureConfig() {

	if g.Config == nil {
		g.Config = NewConfig()
	}

	g.Config.Pub = g.PublicKey()
	g.Config.Props = g.Props.Clone()
	for pubkey, peer := range g.Peers {
		g.Config.Peers[pubkey] = peer.Properties
	}

}

func (g *Principal) SignConfig() error {
	g.ensureConfig()

	g.Config.ensureNonce(g.randomness)

	digest, err := g.Config.Digest()
	if err != nil {
		return err
	}

	sig, err := g.Principal.Sign(nil, digest, nil)
	if err != nil {
		return err
	}

	g.Config.Verity.Signature = sig
	return nil
}

func (g Principal) VerifyConfig() error {

	pub := g.PublicKey()
	dig, err := g.Config.Digest()
	if err != nil {
		return err
	}
	sig := g.Config.Verity.Signature
	ok := g.Principal.Verify(pub, dig, sig)
	if !ok {
		return errors.New("verification failed")
	}
	return nil
}

// Compose creates a message for a recipient. It's syntactic sugar for [delphi.NewMessage]
func (g Principal) Compose(body []byte, headers *KV, recipient Peer) *delphi.Message {
	msg := delphi.NewMessage(g.randomness, body)
	msg.Recipient = recipient.Key
	msg.Sender = g.PublicKey()
	return msg
}

// Art returns the ASCII art representing a public key.
// It can be used for easy visual identification.
func (g Principal) Art() string {
	return g.AsPeer().Art()
}

// func (g Gork) Encrypt(randy io.Reader, msg *delphi.Message, opts any) error {
// 	return msg.Encrypt(randy, g, nil)
// }

// func (g Gork) Decrypt(msg *delphi.Message) error {
// 	return g.Principal.Decrypt(msg *delphi.Message, opts crypto.DecrypterOpts)
// }

// NewPrincipal creates a new [Principal].
func NewPrincipal(randy io.Reader, m map[string]string) Principal {
	prince := delphi.NewPrincipal(randy)
	peers := make(map[delphi.Key]Peer, 8) // 8 seems like a reasonable soft upper limit
	sm := NewKV()
	king := Principal{*prince, sm, peers, randy, NewConfig()}
	err := king.ensureGrip()
	if err != nil {
		panic(err)
	}
	sm.Incorporate(m)

	return king
}

func (g *Principal) ensureGrip() error {

	g.Props.Unshift("grip", g.AsPeer().Grip())
	return nil

	// i := g.Props.IndexOf("grip")
	// if i == 0 {
	// 	return nil
	// }
	// if i == -1 {
	// 	if g.Props.Length() > 0 {
	// 		return errors.New("grip does not exist, and there are other keys")
	// 	}
	// 	g.Props.Set("grip", g.AsPeer().Grip())
	// 	return nil
	// }
	// return errors.New("grip exists but in the wrong position")
}

func (g *Principal) WithRand(randy io.Reader) {
	g.randomness = randy
}

func (g *Principal) WithConfigFile(fd afero.File) error {

	conf := NewConfig()
	b, err := io.ReadAll(fd)
	if err != nil {
		return pear.Errorf("could not read config file. %w", err)
	}
	err = json.Unmarshal(b, conf)
	if err != nil {
		//	if this is not JSON, truncate it
		//fd.Truncate(0)

		//	not an error

		//return pear.Errorf("could not unmarshal config file. %w", err)
		//return pear.New("could not do shitzz")
	}
	conf.File = fd
	g.Config = conf
	g.LoadConfig()
	return nil
}

// load a config file and attach data to a [Principal]
func (g *Principal) LoadConfig() error {
	if g.Config == nil {
		return nil
	}
	for key, props := range g.Config.Peers {
		p := Peer{key, props}
		g.Peers[key] = p
	}
	g.Props.Import(g.Config.Props)
	return nil
}

// Save writes the Principal's Peers and custom properties to a config file
func (g *Principal) Save(fd afero.File) error {

	if g == nil {
		return pear.New("nil principal")
	}

	if fd == nil {
		fd = g.Config.File
	}
	if fd == nil {
		return pear.New("no file specified or found")
	}

	conf := g.Config
	conf.Props = g.Props

	for k, p := range g.Peers {
		conf.Peers[k] = p.Properties
	}
	conf.Pub = g.PublicKey()

	err := g.SignConfig()
	if err != nil {
		return err
	}

	confBytes, err := json.MarshalIndent(conf, "", "\t")
	if err != nil {
		return err
	}

	err = fd.Truncate(0)
	if err != nil {
		return err
	}
	_, err = fd.Seek(0, 0)
	if err != nil {
		return err
	}
	_, err = fd.WriteAt(confBytes, 0)
	if err != nil {
		return err
	}
	err = fd.Sync()
	if err != nil {
		return err
	}
	err = fd.Close()
	if err != nil {
		return err
	}
	return nil
}

// HasPeer returns true if the Principal has knowlege of that Peer
func (g *Principal) HasPeer(p Peer) bool {
	_, exists := g.Peers[p.Key]
	return exists
}

var ErrPeerExists = pear.Defer("peer already exists")

// DropPeer makes a Principal forget a Peer.
func (g *Principal) DropPeer(p Peer) {
	delete(g.Peers, p.Key)
}

// AddPeer adds a Peer to a Principal's address book.
func (g *Principal) AddPeer(p Peer) error {
	if g.HasPeer(p) {
		return ErrPeerExists
	}
	g.Peers[p.Key] = p
	return nil
}

// AsPeer converts a Principal (public and private key) to a Peer (just public key)
func (g *Principal) AsPeer() Peer {
	g.SignConfig()
	k := g.PublicKey()
	//g.ensureGrip()
	return Peer{k, g.Props.Clone()}
}

// MarshalPEM marshals a Principal to PEM format
func (g *Principal) MarshalPEM() ([]byte, error) {
	headers := g.Props.AsMap()
	//headers["grip"] = g.AsPeer().Grip()
	headers["pubkey"] = base64.StdEncoding.EncodeToString(g.AsPeer().Bytes())

	block := &pem.Block{
		Type:    "ORACLE PRIVATE KEY",
		Headers: headers,
		Bytes:   g.PrivateKey().Bytes(),
	}
	return pem.EncodeToMemory(block), nil
}

var ErrBadPem = pear.Defer("malformed pem")
var ErrBadHex = pear.Defer("bad hex")

// UnmarshalPEM converts a PEM to a Principal
func (g *Principal) UnmarshalPEM(b []byte) error {
	block, _ := pem.Decode(b)
	if block == nil {
		return pear.Errorf("could not decode pem. %w", ErrBadPem)
	}
	privkey := block.Bytes
	pub64, exists := block.Headers["pubkey"]
	if !exists {
		return ErrNoPubKey.Throw(1)
	}
	pub, err := base64.StdEncoding.DecodeString(pub64)
	if err != nil {
		return pear.Errorf("%w: %w", ErrBadHex, err)
	}

	sm := stablemap.From(block.Headers)

	kp := delphi.KeyPair{}
	kp[0] = delphi.Key{}.From(pub)
	kp[1] = delphi.Key{}.From(privkey)
	g.Principal = kp
	g.Props = &sm
	g.Props.Delete("grip") // this is derived
	return nil
}

func (g *Principal) FromPem(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return g.UnmarshalPEM(b)
}

func (g *Principal) FromBin(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return g.UnmarshalBinary(b)
}

// PrincipalFrom assumes binary format, but maybe it should assume PEM
func PrincipalFrom(r io.Reader) (*Principal, error) {
	p := new(Principal)
	err := p.FromBin(r)
	return p, err
}
