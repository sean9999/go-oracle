package subcommand

import (
	"encoding/json"
	"errors"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

var lineBreak = []byte("\n")

// Info outputs public information about oneself.
func Info(env *flargs.Environment, globals *ParamSet, _ []string) error {
	if globals.Config == nil {
		return errors.New("config is nil")
	}

	type outputFormat struct {
		Self  oracle.Peer            `json:"self"`
		Peers map[string]oracle.Peer `json:"peers,omitempty"`
	}

	globals.Config.Seek(0, 0)
	me, err := oracle.From(globals.Config)
	if err != nil {
		return err
	}

	ooo := outputFormat{
		Self:  me.AsPeer(),
		Peers: me.Peers(),
	}

	j, err := json.MarshalIndent(ooo, "", "\t")

	// j, err := me.AsPeer().MarshalJSON()
	// if err != nil {
	// 	return err
	// }

	env.OutputStream.Write(j)
	env.OutputStream.Write(lineBreak)

	// if len(me.Peers()) > 0 {
	// 	env.OutputStream.Write(lineBreak)
	// 	env.OutputStream.Write([]byte("peers"))
	// 	env.OutputStream.Write(lineBreak)
	// 	for nick := range me.Peers() {
	// 		env.OutputStream.Write([]byte(nick))
	// 		env.OutputStream.Write(lineBreak)
	// 	}
	// }

	return nil
}
