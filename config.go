package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/BurntSushi/toml"
)

/**
 *	[Self] and [Config] are objects useful for TOML (de)serialization of an [Oracle] or [Peer]
 */

var ErrNotInitialized = errors.New("oracle has not been initialized")
var ErrInvalidConfig = errors.New("invalid config")

var ZeroConf Config

// type Self struct {
// 	EncryptionPrivateKey string `toml:"ePriv"`
// 	EncryptionPublicKey  string `toml:"ePub"`
// 	SigningPrivateKey    string `toml:"sPriv"`
// 	SigningPublicKey     string `toml:"sPub"`
// 	Nickname             string `toml:"Nickname"`
// }

type Self struct {
	PrivateKey string `toml:"priv" json:"priv"`
	PublicKey  string `toml:"pub" json:"pub"`
	Nickname   string `toml:"nick" json:"nick"`
}

type Config struct {
	Self  Self                `toml:"self" json:"self"`
	Peers []map[string]string `toml:"peer" json:"peer"`
}

func (c Config) String() string {
	j, _ := json.Marshal(c)
	return string(j)
}

func (c Config) Valid() bool {
	//	@todo: do we also need to validate the Peers map?
	return c.Self.Valid()
}

func (s Self) Valid() bool {
	if len(s.PrivateKey) != 64 {
		return false
	}
	if len(s.PublicKey) != 128 {
		return false
	}
	if len(s.Nickname) == 0 {
		return false
	}
	//	@todo: check Nickname against calculated nickname
	return true
}

// write an [Oracle] as a [Config] to an [io.Writer]
// @warning: includes Private key. This should be considered secret
func (o *oracle) Export(w io.Writer) error {
	if o.encryptionPrivateKey == nil {
		return ErrNotInitialized
	}
	if o.Peers == nil {
		return ErrNotInitialized
	}

	m := o.AsPeer().AsMap()

	self := Self{
		PrivateKey: hex.EncodeToString(o.encryptionPrivateKey.Bytes()),
		PublicKey:  m["pub"],
		Nickname:   o.Nickname(),
	}
	//	these acrobatics are necessary for clean and readable TOML
	mpeers := make([]map[string]string, 0, len(o.Peers))
	for nick, p := range o.Peers {
		pHex, err := p.MarshalHex()
		if err == nil {
			p := map[string]string{
				"Nickname": nick,
				"pub":      string(pHex),
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

func (o *oracle) configure(conf Config) error {
	o.initialize()

	//	@todo: check calculated values against saved values
	//	panic or barf if there is mismatch

	ePrivBin, err := hex.DecodeString(conf.Self.PrivateKey)
	if err != nil {
		return err
	}
	ePriv, _ := ecdh.X25519().NewPrivateKey(ePrivBin)
	ePub := ePriv.PublicKey()
	o.encryptionPrivateKey = ePriv
	o.EncryptionPublicKey = ePub
	o.signingPrivateKey = ed25519.NewKeyFromSeed(ePrivBin)
	o.SigningPublicKey = o.signingPrivateKey.Public().(ed25519.PublicKey)

	if conf.Peers != nil {
		for _, pMap := range conf.Peers {
			if pMap["nick"] != "" {
				p, err := PeerFromHex([]byte(pMap["pub"]))
				if err == nil {
					o.Peers[pMap["nick"]] = p
				}
			}
		}
	}
	return nil
}

func ConfigFrom(r io.Reader) (Config, error) {
	if r == nil {
		return ZeroConf, errors.New("nil reader")
	}
	tomlDecoder := toml.NewDecoder(r)
	var conf Config
	_, err := tomlDecoder.Decode(&conf)
	if err != nil {
		return ZeroConf, err
	}
	if !conf.Valid() {
		return ZeroConf, ErrInvalidConfig
	}
	return conf, nil
}

// Load an oracle from a Config
// func (o *oracle) Load(r io.Reader) error {
// 	tomlDecoder := toml.NewDecoder(r)
// 	var conf Config
// 	_, err := tomlDecoder.Decode(&conf)
// 	if err != nil {
// 		return err
// 	}
// 	if !conf.Valid() {
// 		return ErrInvalidConfig
// 	}
// 	return o.configure(conf)
// }

func (o *oracle) Load(r io.Reader) error {
	conf, err := ConfigFrom(r)
	if err != nil {
		return err
	}
	return o.configure(conf)
}
