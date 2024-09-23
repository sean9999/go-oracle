package subcommand

import (
	"fmt"
	"math/rand"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

// Init creates a new Oracle. You must pass in a valid path to a file, where the private key information will be held
func Init(env *flargs.Environment, settings *ParamSet) error {

	randy := rand.New(env.Randomness)
	me := oracle.New(randy)
	if settings.Config == nil {
		me.Export(env.OutputStream, false)
		return nil
	}
	me.Export(settings.Config, false)
	path := settings.Config.Name()
	nick := me.AsPeer().Nickname()
	fmt.Fprintf(env.OutputStream, "%q was written to %q\n", nick, path)

	return nil

}
