package oracle

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"

	"github.com/BurntSushi/toml"
)

var ZeroKey ed25519.PublicKey

type Self struct {
	PrivateKey string `toml:"PrivateKey"`
	PublicKey  string `toml:"PublicKey"`
	Nickname   string `toml:"Nickname"`
}

type Config struct {
	Self  Self                `toml:"self"`
	Peers []map[string]string `toml:"peer"`
}

func (o *oracleMachine) Export(w io.Writer) error {
	if o.privateKey == nil {
		return errors.New("oracle has not been initialized")
	}
	if o.peers == nil {
		return errors.New("oracle has not been initialized")
	}
	self := Self{
		PrivateKey: hex.EncodeToString(o.privateKey),
		PublicKey:  hex.EncodeToString(o.publicKey),
		Nickname:   o.Nickname(),
	}
	mpeers := make([]map[string]string, 0, len(o.peers))
	for nick, p := range o.peers {
		if !p.PublicKey.Equal(ZeroKey) {
			p := map[string]string{
				"Nickname":  nick,
				"PublicKey": hex.EncodeToString(p.PublicKey),
			}
			mpeers = append(mpeers, p)
		}
	}
	conf := Config{
		Self:  self,
		Peers: mpeers,
	}
	err := toml.NewEncoder(w).Encode(conf)
	return err
}

func (o *oracleMachine) Configure(conf Config) error {
	o.Initialize()
	privSeed := make([]byte, 64)
	hex.Decode(privSeed, []byte(conf.Self.PrivateKey))
	priv := ed25519.NewKeyFromSeed(privSeed[:32])
	pub := priv.Public()
	o.privateKey = priv
	o.publicKey = pub.(ed25519.PublicKey)
	if conf.Peers != nil {
		for _, p := range conf.Peers {
			if p["PublicKey"] != "" {
				o.peers[p["Nickname"]] = PeerFromHex(p["PublicKey"]).(Peer)
			}
		}
	}
	return nil
}

func (o *oracleMachine) Load(r io.Reader) error {
	tomlDecoder := toml.NewDecoder(r)
	var conf Config
	_, err := tomlDecoder.Decode(&conf)
	if err != nil {
		return err
	}
	return o.Configure(conf)
}
