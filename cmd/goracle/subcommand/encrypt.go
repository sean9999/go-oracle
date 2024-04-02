package subcommand

import (
	"bytes"
	"flag"
	"fmt"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

// looks for a  "--to" flag with a value that _seems_ like it could identify a real peer.
func parseEncryptParams(args []string) (string, []string, error) {
	var to string
	fset := flag.NewFlagSet("encrypt params", flag.ContinueOnError)
	fset.Func("to", "who to send to", func(s string) error {
		if looksLikeHexPubkey(s) {
			_, err := oracle.PeerFromHex([]byte(s))
			if err != nil {
				return err
			}
			to = s
			return nil
		}
		if looksLikeNickname(s) {
			to = s
			return nil
		}
		return NewOracleError(fmt.Sprintf("%q does not look like a pubkey or nickname %d", s, len(s)), nil)
	})
	err := fset.Parse(args[1:])
	return to, fset.Args(), err
}

// Encrypt encrypts a message to a recipient passed in the "--to" argument
func Encrypt(env *flargs.Environment, globals *ParamSet, args []string) error {

	//	parse args
	toStr, _, err := parseEncryptParams(args)
	if err != nil {
		return err
	}

	//	get peer
	me := globals.Me
	var recipient oracle.Peer
	if len(toStr) < 64 {
		recipient, err = me.Peer(toStr)
		if err != nil {
			return err
		}
	} else {
		recipient, err = oracle.PeerFromHex([]byte(toStr))
		if err != nil {
			return err
		}
	}

	//	read bytes from stdin
	inPlainBytes := new(bytes.Buffer)
	inPlainBytes.ReadFrom(env.InputStream)
	pt := me.Compose("encrypted message", inPlainBytes.Bytes())

	//	encrypt
	cipherText, err := me.Encrypt(pt, recipient)
	if err != nil {
		return err
	}

	//	serialize
	var cipherTextAsBytes []byte
	if globals.Format == "pem" {
		cipherTextAsBytes, err = cipherText.MarshalPEM()
		if err != nil {
			return err
		}
	} else {
		cipherTextAsBytes, err = cipherText.MarshalIon()
		if err != nil {
			return err
		}
	}

	//	write
	env.OutputStream.Write(cipherTextAsBytes)

	return nil

}
