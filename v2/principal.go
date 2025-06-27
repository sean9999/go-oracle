package goracle

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	"maps"

	"github.com/sean9999/go-delphi"
	stablemap "github.com/sean9999/go-stable-map"
)

type Principal struct {
	delphi.Principal
	Props *stablemap.StableMap[string, string]
	Peers PeerStore
}

type principalRecord struct {
	Priv  string            `json:"priv"`
	Pub   string            `json:"pub"`
	Nick  string            `json:"nick"`
	Props map[string]string `json:"props"`
	Peers map[string]*Peer  `json:"peers"`
}

func NewPrincipal(rand io.Reader, props map[string]string) *Principal {

	var keys delphi.Principal
	if rand != nil {
		keys = delphi.NewPrincipal(rand)
	}

	sm := stablemap.From(props)
	peermap := stablemap.New[string, *Peer]()
	p := Principal{
		keys,
		sm,
		peermap,
	}
	return &p
}

func (p *Principal) MarshalPEM() (*pem.Block, error) {
	block, err := p.Principal.MarshalPEM()
	if err != nil {
		return &block, err
	}
	maps.Insert(block.Headers, p.Props.Entries())
	return &block, nil
}

func (p *Principal) MarshalJSON() ([]byte, error) {
	s := principalRecord{}
	s.Priv = p.PrivateKey().ToHex()
	s.Pub = p.PublicKey().ToHex()
	s.Nick = p.Nickname()
	s.Props = p.Props.AsMap()
	s.Peers = p.Peers.AsMap()
	return json.Marshal(s)
}

func (p *Principal) UnmarshalJSON(data []byte) error {
	s := new(principalRecord)
	err := json.Unmarshal(data, s)
	if err != nil {
		return err
	}
	privKey := delphi.KeyFromHex(s.Priv)
	pubKey := delphi.KeyFromHex(s.Pub)
	keyChain := delphi.KeyPair{}
	copy(keyChain[1][:], privKey[:])
	copy(keyChain[0][:], pubKey[:])
	realNick := keyChain.Nickname()
	supposedNick := s.Nick
	if realNick != supposedNick {
		return fmt.Errorf("%q is not %q", supposedNick, realNick)
	}
	p.Principal = keyChain
	p.Props = stablemap.From(s.Props)
	p.Peers = stablemap.From(s.Peers)
	return nil
}

func (p *Principal) UnmarshalPEM(block *pem.Block) error {
	err := p.Principal.UnmarshalPEM(*block)
	if err != nil {
		return err
	}
	p.Props = stablemap.From(block.Headers)
	return nil
}

func (p *Principal) ToPeer() *Peer {

	peer := Peer{}.FromPrincipal(p)

	return peer
}

func (p *Principal) Save(w io.Writer) error {
	j, err := p.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(j)
	if err != nil {
		return err
	}
	wc, ok := w.(io.Closer)
	if ok {
		err = wc.Close()
	}
	return err
}

func LoadPrincipal(r io.Reader) (*Principal, error) {
	p := new(Principal)
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	err = p.UnmarshalJSON(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return p, nil
}
