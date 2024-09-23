package oracle

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
)

/**
 *	[Self] and [Config] are objects useful for TOML (de)serialization of an [Oracle] or [Peer]
 */

var (
	ErrNotInitialized = errors.New("oracle has not been initialized")
	ErrInvalidConfig  = errors.New("invalid config")
)

var ZeroConf Config

// type Self struct {
// 	EncryptionPrivateKey string `toml:"ePriv"`
// 	EncryptionPublicKey  string `toml:"ePub"`
// 	SigningPrivateKey    string `toml:"sPriv"`
// 	SigningPublicKey     string `toml:"sPub"`
// 	Nickname             string `toml:"Nickname"`
// }

type Self struct {
	PrivateKey string `json:"priv"`
	PublicKey  string `json:"pub"`
	Nickname   string `json:"nick"`
}

type Config struct {
	Self  Self                         `json:"self"`
	Peers map[string]map[string]string `json:"peers"`
}

// func (c Config) MarshalTOML() ([]byte, error) {
// 	buf := new(bytes.Buffer)
// 	enc := toml.NewEncoder(buf)
// 	err := enc.Encode(c)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

func (c Config) String() string {

	j, _ := json.Marshal(c)
	return string(j)

	// b, err := c.MarshalTOML()
	// if err != nil {
	// 	panic(err)
	// }
	// return string(b)
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
	//	@todo: ensure keys match and are valid points on the ed25519 curve
	return true
}

func (o *Oracle) Save() error {
	return o.Export(o.Provenance, false)
}

// write an [Oracle] as a [Config] to an [io.Writer]
// @warning: includes Private key. This should be considered secret
func (o *Oracle) Export(w io.ReadWriter, andClose bool) error {

	if andClose {
		if closer, canClose := w.(io.Closer); canClose {
			defer closer.Close()
		}
	}

	//	rewind
	wf, ok := w.(*os.File)
	if ok {
		wf.Truncate(0)
		wf.Seek(0, 0)
	}

	if o.encryptionPrivateKey == nil {
		return ErrNotInitialized
	}
	if o.peers == nil {
		return ErrNotInitialized
	}

	m := o.AsPeer().AsMap()

	self := Self{
		PrivateKey: hex.EncodeToString(o.encryptionPrivateKey.Bytes()),
		PublicKey:  m["pub"],
		Nickname:   o.Nickname(),
	}
	//	these acrobatics are necessary for clean and readable TOML
	//mpeers := make([]map[string]string, 0, len(o.peers))

	mpeers := make(map[string]map[string]string, len(o.peers))

	for nick, p := range o.peers {
		pHex, err := p.MarshalHex()
		if err == nil {
			p := map[string]string{
				"nick": nick,
				"pub":  string(pHex),
			}
			mpeers[nick] = p
		}
	}
	conf := Config{
		Self:  self,
		Peers: mpeers,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	err := enc.Encode(conf)
	return err
}

func (o *Oracle) configure(conf Config) error {
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
					o.peers[pMap["nick"]] = p
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
	jsonDecoder := json.NewDecoder(r)
	var conf Config
	err := jsonDecoder.Decode(&conf)
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

func (o *Oracle) Load(r io.Reader) error {
	conf, err := ConfigFrom(r)
	if err != nil {
		return err
	}
	return o.configure(conf)
}
