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
	EncryptionPrivateKey string `toml:"ePriv"`
	EncryptionPublicKey  string `toml:"ePub"`
	SigningPrivateKey    string `toml:"sPriv"`
	SigningPublicKey     string `toml:"sPub"`
	Nickname             string `toml:"Nickname"`
}

type Config struct {
	Self  Self                `toml:"self"`
	Peers []map[string]string `toml:"peer"`
}

// write an [Oracle] as a [Config] to an [io.Writer]
// @warning: includes Private key. This should be considered secret
func (o *Oracle) Export(w io.Writer) error {
	if o.EncryptionPrivateKey == nil {
		return ErrNotInitialized
	}
	if o.Peers == nil {
		return ErrNotInitialized
	}
	self := Self{
		EncryptionPrivateKey: hex.EncodeToString(o.EncryptionPrivateKey.Bytes()),
		EncryptionPublicKey:  hex.EncodeToString(o.EncryptionPublicKey.Bytes()),
		SigningPrivateKey:    hex.EncodeToString(o.SigningPrivateKey),
		SigningPublicKey:     hex.EncodeToString(o.SigningPublicKey),
		Nickname:             o.Nickname(),
	}
	//	these acrobatics are necessary for clean and readable TOML
	mpeers := make([]map[string]string, 0, len(o.Peers))
	for nick, p := range o.Peers {
		if p.EncryptionPublicKey != nil {
			p := map[string]string{
				"Nickname": nick,
				"ePub":     hex.EncodeToString(p.EncryptionPublicKey.Bytes()),
				"sPub":     hex.EncodeToString(p.SigningPublicKey),
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

func (o *Oracle) configure(conf Config) error {
	o.initialize()

	//privSeed := make([]byte, 32)
	//hex.Decode(privSeed, []byte(conf.Self.PrivateKey))

	ePrivBin, err := hex.DecodeString(conf.Self.EncryptionPrivateKey)
	if err != nil {
		return err
	}
	ePriv, _ := ecdh.X25519().NewPrivateKey(ePrivBin)
	ePub := ePriv.PublicKey()
	o.EncryptionPrivateKey = ePriv
	o.EncryptionPublicKey = ePub

	sPriv, err := hex.DecodeString(conf.Self.SigningPrivateKey)
	if err != nil {
		return err
	}
	sPub, err := hex.DecodeString(conf.Self.SigningPublicKey)
	if err != nil {
		return err
	}
	o.SigningPrivateKey = sPriv
	o.SigningPublicKey = sPub
	if conf.Peers != nil {
		for _, p := range conf.Peers {
			if p["sPub"] != "" {
				o.Peers[p["Nickname"]] = PeerFromHex(p["ePub"], p["sPub"])
			}
		}
	}
	return nil
}

// Load an oracle from a Config
func (o *Oracle) Load(r io.Reader) error {
	tomlDecoder := toml.NewDecoder(r)
	var conf Config
	_, err := tomlDecoder.Decode(&conf)
	if err != nil {
		return err
	}
	return o.configure(conf)
}
