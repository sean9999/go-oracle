package oracle

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/sean9999/go-oracle/v3/delphi"
	"io"
)

type Props = map[string]string

type Principal struct {
	Props   Props          `json:"Props"`
	KeyPair delphi.KeyPair `json:"keypair"`
	Peers   PeerStore      `json:"peers"`
}

func (pr *Principal) MarshalPEM() ([]byte, error) {
	pr.expound()
	block := &pem.Block{
		Type:    "ORACLE PRIVATE KEY",
		Headers: pr.Props,
		Bytes:   pr.KeyPair.Bytes(),
	}
	bin := pem.EncodeToMemory(block)
	return bin, nil
}

func (pr *Principal) UnmarshalPEM(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("PEM decode failed")
	}
	if block.Type != "ORACLE PRIVATE KEY" {
		return errors.New("wrong PEM type: " + block.Type)
	}

	kp := delphi.KeyPair{}

	_, err := kp.Write(block.Bytes)
	if err != nil {
		return err
	}
	pr.KeyPair = kp
	pr.Props = block.Headers
	pr.Peers = make(PeerStore)
	pr.condense()
	return nil
}

func (pr *Principal) SaveJSON(w io.Writer) error {
	pr.MustBeValid()
	pr.expound()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(pr)
}

func (pr *Principal) initialize() {
	pr.Props = make(map[string]string)
	pr.Peers = make(PeerStore)
}

// expound() adds derived values to Props.
// Good for situations where you want maximum context.
func (pr *Principal) expound() {
	pr.MustBeValid()
	nick := pr.NickName()
	pr.Props["nick"] = nick
}

// condense() removes derived values from Props.
// Good for brevity and avoiding confusion about which values are derived and which are not.
func (pr *Principal) condense() {
	pr.MustBeValid()
	delete(pr.Props, "nick")
}

func LoadJSON(r io.Reader) (*Principal, error) {
	p := new(Principal)
	p.initialize()
	dec := json.NewDecoder(r)
	err := dec.Decode(p)
	p.condense()
	return p, err
}

func NewPrincipal(randy io.Reader) *Principal {
	keypair := delphi.NewKeyPair(randy)
	//if randy != nil {
	//	keypair[0].MustBeValid()
	//	keypair[1].MustBeValid()
	//}
	p := &Principal{KeyPair: keypair}
	p.initialize()
	p.expound()
	return p
}

func (pr *Principal) MustBeValid() {
	//pr.KeyPair[0].MustBeValid()
	//pr.KeyPair[1].MustBeValid()
	if pr.Props == nil {
		panic("nil Props")
	}
	if pr.Peers == nil {
		panic("nil peers")
	}
}

func (pr *Principal) NickName() string {
	//pr.MustBeValid()
	return pr.KeyPair.PublicKey().Nickname()
}

// ID produces a string that uniquely identifies a Principal
func (pr *Principal) ID() string {
	pr.MustBeValid()
	return pr.NickName()
}

func (pr *Principal) AsPeer() Peer {
	pr.MustBeValid()
	return Peer{
		Props:     pr.Props,
		PublicKey: pr.KeyPair.PublicKey(),
	}
}

func (pr *Principal) AddPeer(peer Peer) {
	//pr.MustBeValid()
	pr.Peers[peer.PublicKey] = peer.Props
}

func (pr *Principal) HasPeer(pub delphi.PublicKey) bool {
	_, ok := pr.Peers[pub]
	return ok
}
