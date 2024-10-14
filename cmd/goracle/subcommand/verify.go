package subcommand

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Verify(env *flargs.Environment, settings *ParamSet) error {

	conf := settings.Config
	me, err := oracle.From(conf)
	if err != nil {
		return err
	}
	settings.Me = me

	signedMsg := new(bytes.Buffer)
	signedMsg.ReadFrom(env.InputStream)

	pt := new(oracle.PlainText)

	if settings.Format == "pem" {
		err := pt.UnmarshalPEM(signedMsg.Bytes())
		if err != nil {
			return err
		}
	} else {
		err := pt.UnmarshalIon(signedMsg.Bytes())
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
		if errors.Is(err, oracle.ErrPeerAlreadyAdded) {
			fmt.Fprintln(env.OutputStream, "Message signature is valid")
			return nil
		}
		if err != nil {
			return err
		}

		err = me.Export(conf, true)
		if err != nil {
			return err
		}

	} else {
		//return errors.New("the assertion could not be validated")
		return NewOracleError("the assertion could not  be validated.", nil)
	}

	fmt.Fprintf(env.OutputStream, "Peer %s was validated and saved to %s\n", asserter.Nickname(), conf.Name())
	conf.Close()

	return nil
}
