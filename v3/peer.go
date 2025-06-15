package goracle

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sean9999/go-delphi"
	stablemap "github.com/sean9999/go-stable-map"
)

type Peer struct {
	Props       stablemap.StableMap[string, string] `json:"props"`
	delphi.Peer `json:"peer"`
}

func (p *Peer) MarshalJSON() ([]byte, error) {
	m := p.Props.AsMap()
	m["pub"] = p.ToHex()
	m["nick"] = p.Nickname()
	return json.Marshal(m)
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	var m map[string]string
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	hexPub, exists := m["pub"]
	if !exists {
		return errors.New("no pub key")
	}
	pub := delphi.KeyFromHex(hexPub)
	delete(m, "pub")
	if pub.Nickname() != m["nick"] {
		return fmt.Errorf("%q is not %q", m["nick"], pub.Nickname())
	}
	delete(m, "nick")
	p.Props = stablemap.From(m)
	return nil
}

func (Peer) FromPrincipal(prince *Principal) *Peer {
	if prince == nil {
		return nil
	}
	pubkey := prince.PublicKey()
	pee := Peer{
		Peer:  pubkey,
		Props: *prince.Props.Clone(),
	}
	return &pee
}
