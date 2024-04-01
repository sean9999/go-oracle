package subcommand

import (
	"errors"
	"fmt"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Init(env *flargs.Environment, settings map[string]any) error {

	me := oracle.New(env.Randomness)

	conf, ok := settings["config"].(*os.File)
	if !ok {
		return errors.New("could not coerce config")
	}
	me.Export(conf)

	path := conf.Name()
	nick := me.AsPeer().Nickname()

	output := fmt.Sprintf("%q was written to %q", nick, path)

	fmt.Fprintln(env.OutputStream, output)

	return nil

}
