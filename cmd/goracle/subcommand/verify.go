package subcommand

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Verify(env *flargs.Environment, settings map[string]any) error {

	conf, ok := settings["config"].(*os.File)
	if !ok {
		return errors.New("conf could not be coerced")
	}

	me, err := oracle.From(conf)
	if err != nil {
		return err
	}

	signedMsg := new(bytes.Buffer)
	signedMsg.ReadFrom(env.InputStream)

	pt := new(oracle.PlainText)

	if settings["format"] == "pem" {
		err = pt.UnmarshalPEM(signedMsg.Bytes())
		if err != nil {
			return err
		}
	} else {
		err = pt.UnmarshalIon(signedMsg.Bytes())
		if err != nil {
			return err
		}
	}

	pubHex, ok := pt.Headers["pubkey"]
	if !ok {
		return errors.New("there was no 'pubkey' header")
	}

	asserter, err := oracle.PeerFromHex([]byte(pubHex))
	if err != nil {
		return err
	}

	ok = me.Verify(pt, asserter)

	if ok {
		err = me.AddPeer(asserter)
		if err != nil {
			return err
		}
		err = me.Export(conf)
		if err != nil {
			return err
		}

	} else {
		//return errors.New("the assertion could not be validated")
		return NewOracleError("the assertion could not  be validated.", nil)
	}

	fmt.Fprintf(env.OutputStream, "Peer %s was added and saved to %s", asserter.Nickname(), conf.Name())
	conf.Close()

	return nil
}
