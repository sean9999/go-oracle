package subcommand

import (
	"bytes"
	"errors"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Sign(env *flargs.Environment, settings map[string]any) error {

	conf, ok := settings["config"].(*os.File)
	if !ok {
		return errors.New("conf could not be coerced")
	}

	me, err := oracle.From(conf)
	if err != nil {
		return err
	}

	rawMsg := new(bytes.Buffer)
	rawMsg.ReadFrom(env.InputStream)

	pt := me.Compose("signed message", rawMsg.Bytes())
	err = pt.Sign(env.Randomness, me.PrivateSigningKey())
	if err != nil {
		return err
	}

	var art []byte

	if settings["format"] == "pem" {
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
