package subcommand

import (
	"errors"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

// Assert creates a signed assertion others can use to verify and trust you
func Assert(env *flargs.Environment, globals ParamSet) error {
	if globals.Config == nil {
		return errors.New("config is nil")
	}
	globals.Config.Seek(0, 0)
	me, err := oracle.From(globals.Config)
	if err != nil {
		return err
	}

	pt, err := me.Assert()

	if err != nil {
		return err
	}

	pem, err := pt.MarshalPEM()
	if err != nil {
		return err
	}

	env.OutputStream.Write(pem)

	return nil
}
