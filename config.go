package oracle

import (
	"errors"
	"io"

	"github.com/BurntSushi/toml"
)

type Self struct {
	PrivateKey string `toml:"PrivateKey"`
	PublicKey  string `toml:"PublicKey"`
	Nickname   string `toml:"Nickname"`
}

type Config struct {
	Self  Self   `toml:"self"`
	Peers []Peer `toml:"peer"`
}

func (o *Oracle) Export(w io.Writer) error {

	if o.privateKey == nil {
		return errors.New("Oracle has not been initialized")
	}

	if o.peers == nil {
		return errors.New("Oracle has not been initialized")
	}

	self := Self{
		PrivateKey: o.PrivateKeyAsHex(),
		PublicKey:  o.PublicKeyAsHex(),
		Nickname:   o.Nickname(),
	}
	peers := []Peer{}

	for _, p := range o.peers {
		peers = append(peers, p)
	}

	conf := Config{
		Self:  self,
		Peers: peers,
	}
	err := toml.NewEncoder(w).Encode(conf)

	return err
}

func (o *Oracle) Configure(conf Config) error {
	priv, err := PrivateKeyFromHex(conf.Self.PrivateKey)
	if err != nil {
		return err
	}
	o.privateKey = &priv
	for _, p := range conf.Peers {
		o.peers[p.Nickname()] = p
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
