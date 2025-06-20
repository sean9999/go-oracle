package goracle

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"
	stablemap "github.com/sean9999/go-stable-map"
)

type Peer struct {
	Props       *stablemap.StableMap[string, string] `json:"props"`
	delphi.Peer `json:"peer"`
}

func NewPeer() *Peer {
	p := Peer{
		Props: stablemap.New[string, string](),
		Peer:  delphi.NewPeer(),
	}
	return &p
}

func (Peer) From(data []byte, plainMap map[string]string) *Peer {
	return PeerFrom(data, plainMap)
}

func PeerFrom(data []byte, plainMap map[string]string) *Peer {
	//	TODO: panic or error if the byte slice looks wrong
	p := Peer{
		Peer:  delphi.Key{}.From(data),
		Props: stablemap.New[string, string](),
	}
	p.Props.Incorporate(plainMap)
	return &p
}

func (p *Peer) MarshalJSON() ([]byte, error) {
	m := p.Props.AsMap()
	m["pub"] = p.ToHex()
	m["nick"] = p.Nickname()
	delete(m, "pub")
	delete(m, "nick")
	p.Props = stablemap.From(m)
	return json.Marshal(m)
}

func (p *Peer) MarshalPEM() (*pem.Block, error) {
	block, err := p.Peer.MarshalPEM()
	if err != nil {
		return nil, err
	}
	block.Headers = p.Props.AsMap()
	block.Headers["nick"] = p.Nickname()
	return &block, nil
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	m := make(map[string]string)
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	hexPub, exists := m["pub"]
	if !exists {
		return errors.New("no pub key")
	}
	pub := delphi.KeyFromHex(hexPub)
	//delete(m, "pub")
	if pub.Nickname() != m["nick"] {
		return fmt.Errorf("%q is not %q", m["nick"], pub.Nickname())
	}

	p.Peer = pub

	return nil
}

func (Peer) FromPrincipal(prince *Principal) *Peer {
	if prince == nil {
		return nil
	}
	pubkey := prince.PublicKey()
	pee := Peer{
		Peer:  pubkey,
		Props: prince.Props.Clone(),
	}
	return &pee
}
