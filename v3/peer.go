package oracle

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"oracle2/delphi"
)

type Peer struct {
	Props     map[string]string `json:"Props"`
	PublicKey delphi.PublicKey  `json:"pubkey"`
}

func (p *Peer) NickName() string {
	return p.PublicKey.Nickname()
}

func (p *Peer) Save(w io.Writer) error {
	delphi.Key(p.PublicKey).MustBeValid()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(p)
}

func (p *Peer) MarshalPEM() ([]byte, error) {
	p.expound()
	block := &pem.Block{
		Type:    "ORACLE PEER",
		Headers: p.Props,
		Bytes:   p.PublicKey.Bytes(),
	}
	bin := pem.EncodeToMemory(block)
	return bin, nil
}

func (p *Peer) UnmarshalPEM(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("PEM decode failed")
	}
	if block.Type != "ORACLE PEER" {
		return errors.New("wrong PEM type: " + block.Type)
	}
	_, err := p.PublicKey.Write(block.Bytes)
	if err != nil {
		return err
	}
	p.Props = block.Headers
	p.condense()
	return nil
}

// expound adds derived values to Props.
// Good for situations where you want maximum context.
func (p *Peer) expound() {
	nick := p.NickName()
	p.Props["nick"] = nick
}

// condense removes derived values from Props.
// Good for brevity and avoiding confusion about which values are derived and which are not.
func (p *Peer) condense() {
	delete(p.Props, "nick")
}
