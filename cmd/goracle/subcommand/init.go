package subcommand

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

// Init creates a new Oracle. You must pass in a valid path to a file, where the private key information will be held
func Init(env *flargs.Environment, settings *ParamSet) error {

	randy := rand.New(env.RandSource)
	me := oracle.New(randy)
	if settings.Config == nil {
		return errors.New("nil config")
	}
	me.Export(settings.Config)
	path := settings.Config.Name()
	nick := me.AsPeer().Nickname()
	fmt.Fprintf(env.OutputStream, "%q was written to %q", nick, path)

	return nil

}
