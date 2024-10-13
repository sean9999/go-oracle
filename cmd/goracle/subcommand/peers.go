package subcommand

import (
	"encoding/json"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Peers(env *flargs.Environment, globals *ParamSet) error {

	me, err := oracle.From(globals.Config)
	if err != nil {
		return err
	}
	j, err := json.MarshalIndent(me.Peers(), "", "\t")
	if err != nil {
		return err
	}

	env.OutputStream.Write(j)
	env.OutputStream.Write([]byte("\n"))

	return nil
}
