package subcommand

import (
	"encoding/json"

	"github.com/sean9999/go-flargs"
)

func Peers(env *flargs.Environment, globals *ParamSet) error {

	me := globals.Me

	peers := map[string]string{}
	for _, pr := range me.Peers() {
		m := pr.AsMap()
		peers[m["nick"]] = m["pub"]
	}
	j, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}

	env.OutputStream.Write(j)

	return nil
}
