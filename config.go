package oracle

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"io"

	"github.com/BurntSushi/toml"
)

/**
 *	[Self] and [Config] are objects useful for TOML (de)serialization of an [Oracle] or [Peer]
 */

var ErrNotInitialized = errors.New("oracle has not been initialized")

type Self struct {
	PrivateKey string `toml:"PrivateKey"`
	PublicKey  string `toml:"PublicKey"`
	Nickname   string `toml:"Nickname"`
}

type Config struct {
	Self  Self                `toml:"self"`
	Peers []map[string]string `toml:"peer"`
}

func (o *Oracle) Export(w io.Writer) error {

	if o.privateKey == nil {
		return ErrNotInitialized
	}
	if o.peers == nil {
		return ErrNotInitialized
	}
	self := Self{
		PrivateKey: hex.EncodeToString(o.privateKey.Bytes()),
		PublicKey:  hex.EncodeToString(o.publicKey.Bytes()),
		Nickname:   o.Nickname(),
	}
	//	these acrobatics are necessary for clean and readable TOML
	mpeers := make([]map[string]string, 0, len(o.peers))
	for nick, p := range o.peers {
		if p.PublicKey != nil {
			p := map[string]string{
				"Nickname":  nick,
				"PublicKey": hex.EncodeToString(p.PublicKey.Bytes()),
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

func (o *Oracle) Configure(conf Config) error {
	o.Initialize()
	privSeed := make([]byte, 32)
	hex.Decode(privSeed, []byte(conf.Self.PrivateKey))
	priv, _ := ecdh.X25519().NewPrivateKey(privSeed)
	pub := priv.PublicKey()
	o.privateKey = priv
	o.publicKey = pub
	if conf.Peers != nil {
		for _, p := range conf.Peers {
			if p["PublicKey"] != "" {
				o.peers[p["Nickname"]] = PeerFromHex(p["PublicKey"])
			}
		}
	}
	return nil
}

func (o *Oracle) Load(r io.Reader) error {
	tomlDecoder := toml.NewDecoder(r)
	var conf Config
	_, err := tomlDecoder.Decode(&conf)
	if err != nil {
		return err
	}
	return o.Configure(conf)
}
