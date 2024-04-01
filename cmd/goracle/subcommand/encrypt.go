package subcommand

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func looksLikeHexPubkey(s string) bool {
	//	@todo: make this robust
	return len(s) == 128
}

func looksLikeNickname(s string) bool {
	//	@todo: make this robust too
	return (len(s) > 3 && len(s) < 64)
}

func parseArgs(args []string, principal oracle.Oracle, _ *os.File) (marg, []string, error) {
	fl := flargs.NewFlargs(func(args []string) (marg, []string, error) {
		m := marg{
			"hello": true,
		}
		fset := flag.NewFlagSet("encryption params", flag.ContinueOnError)
		fset.Func("to", "who to send to", func(s string) error {
			if looksLikeHexPubkey(s) {
				p, err := oracle.PeerFromHex([]byte(s))
				if err != nil {
					return err
				}
				m["to"] = p
				principal.AddPeer(p)
				//	should we be extra courteous and save the peer to config?
				//	answer: maybe not, because this pubkey did not come with a signed assertion
				//	in fact, maybe we should dissalow this if peer is not already known and trusted
				//principal.Export(conf)
				return nil
			}
			if looksLikeNickname(s) {
				p, err := principal.Peer(s)
				if err != nil {
					return err
				}
				m["to"] = p
				return nil
			}
			return NewOracleError(fmt.Sprintf("%q does not look like a pubkey or nickname %d", s, len(s)), nil)
		})
		err := fset.Parse(args)
		return m, fset.Args(), err
	})
	return fl.Parse(args)
}

func Encrypt(env *flargs.Environment, globals marg, args []string) error {
	thisCommand := args[0]
	if thisCommand != "encrypt" {
		return NewOracleError(fmt.Sprintf("was expecting subcomand to be %q, but it was %q", "encrypt", thisCommand), nil)
	}
	conf, ok := globals["config"].(*os.File)
	if !ok {
		return NewOracleError("could not coerce config", nil)
	}
	me, err := oracle.From(conf)
	if err != nil {
		return NewOracleError("could not hydrate principal from config", nil)
	}
	m, _, err := parseArgs(args[1:], me, conf)
	if err != nil {
		return err
	}
	recipient, ok := m["to"].(oracle.Peer)
	if !ok {
		return NewOracleError("could not hydrate Peer from marg[to]", nil)
	}

	// eat up stdin bytes
	inPlainBytes := new(bytes.Buffer)
	inPlainBytes.ReadFrom(env.InputStream)
	pt := me.Compose("encrypted message", inPlainBytes.Bytes())

	//	encrypt
	cipherText, err := me.Encrypt(pt, recipient)
	if err != nil {
		return err
	}

	var cipherTextAsBytes []byte

	if globals["format"] == "pem" {
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

	env.OutputStream.Write(cipherTextAsBytes)

	//fmt.Fprintln(env.OutputStream, "marg ", m)
	//fmt.Fprintln(env.OutputStream, "tail ", tail)
	//fmt.Fprintln(env.ErrorStream, "err ", err)

	return nil

	//return NewOracleError("encrypt subcommand", ErrNotImplemented)

}
