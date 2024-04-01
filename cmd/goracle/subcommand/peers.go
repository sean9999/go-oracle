package subcommand

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Peers(env *flargs.Environment, globals marg) error {
	if globals["config"] == nil {
		return errors.New("config is nil")
	}
	conf, ok := globals["config"].(*os.File)
	if !ok {
		return errors.New("could not coerce config to *os.File")
	}
	conf.Seek(0, 0)
	me, err := oracle.From(conf)
	if err != nil {
		return err
	}

	//peers := []map[string]string{}
	peers := map[string]string{}
	for _, pr := range me.Peers() {
		m := pr.AsMap()
		peers[m["nick"]] = m["pub"]
		//peers = append(peers, m)
	}
	j, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}

	env.OutputStream.Write(j)

	return nil
}
