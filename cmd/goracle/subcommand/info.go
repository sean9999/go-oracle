package subcommand

import (
	"errors"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

type marg = map[string]any

func Info(env *flargs.Environment, globals marg, args []string) error {
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

	j, err := me.AsPeer().MarshalJSON()
	if err != nil {
		return err
	}

	env.OutputStream.Write(j)

	return nil
}
