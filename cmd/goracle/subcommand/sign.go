package subcommand

import (
	"bytes"
	"math/rand"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Sign(env *flargs.Environment, settings *ParamSet) error {

	conf := settings.Config

	me, err := oracle.From(conf)
	if err != nil {
		return err
	}
	settings.Me = me

	rawMsg := new(bytes.Buffer)
	rawMsg.ReadFrom(env.InputStream)

	pt := me.Compose("signed message", rawMsg.Bytes())
	randy := rand.New(env.Randomness)
	err = pt.Sign(randy, me.PrivateSigningKey())
	if err != nil {
		return err
	}

	var art []byte

	if settings.Format == "pem" {
		art, err = pt.MarshalPEM()
		if err != nil {
			return err
		}
	} else {
		art, err = pt.MarshalIon()
		if err != nil {
			return err
		}
	}

	env.OutputStream.Write(art)
	return nil
}
