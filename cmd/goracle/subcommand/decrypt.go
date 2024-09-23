package subcommand

import (
	"bytes"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

// Decrypt decrypts an encrypted message
func Decrypt(env *flargs.Environment, globals *ParamSet, _ []string) error {

	conf := globals.Config
	me, err := oracle.From(conf)
	if err != nil {
		return err
	}
	globals.Me = me

	// read ciphertext
	ct := new(oracle.CipherText)
	inBytes := new(bytes.Buffer)
	inBytes.ReadFrom(env.InputStream)
	ct.UnmarshalPEM(inBytes.Bytes())
	pt, err := me.Decrypt(ct)
	if err != nil {
		return err
	}

	//	serialize
	ptBytes, err := pt.MarshalPEM()
	if err != nil {
		return err
	}

	//	write plain text
	env.OutputStream.Write(ptBytes)

	return nil

}
