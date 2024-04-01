package subcommand

import (
	"bytes"
	"fmt"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func Decrypt(env *flargs.Environment, globals marg, args []string) error {
	thisCommand := args[0]
	if thisCommand != "decrypt" {
		return NewOracleError(fmt.Sprintf("was expecting subcomand to be %q, but it was %q", "decrypt", thisCommand), nil)
	}
	conf, ok := globals["config"].(*os.File)
	if !ok {
		return NewOracleError("could not coerce config", nil)
	}
	me, err := oracle.From(conf)
	if err != nil {
		return NewOracleError("could not hydrate principal from config", nil)
	}

	// eat up stdin bytes
	ct := new(oracle.CipherText)
	inBytes := new(bytes.Buffer)
	inBytes.ReadFrom(env.InputStream)
	ct.UnmarshalPEM(inBytes.Bytes())
	pt, err := me.Decrypt(ct)
	if err != nil {
		return err
	}

	ptBytes, err := pt.MarshalPEM()
	if err != nil {
		return err
	}

	env.OutputStream.Write(ptBytes)

	//fmt.Fprintln(env.OutputStream, "marg ", m)
	//fmt.Fprintln(env.OutputStream, "tail ", tail)
	//fmt.Fprintln(env.ErrorStream, "err ", err)

	return nil

	//return NewOracleError("encrypt subcommand", ErrNotImplemented)

}
