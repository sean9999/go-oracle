package subcommand

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

func normalizeText(inText string) string {
	r := inText
	r = strings.ReplaceAll(r, "\n", " ")
	r = strings.ReplaceAll(r, "\t", " ")
	r = strings.ReplaceAll(r, "   ", " ")
	r = strings.ReplaceAll(r, "  ", " ")
	r = strings.TrimSpace(r)
	return r
}

func Assert(env *flargs.Environment, globals marg) error {
	if globals["config"] == nil {
		return errors.New("config is nil")
	}
	conf, ok := globals["config"].(*os.File)
	if !ok {
		return errors.New("could not coerce config to *os.File")
	}
	conf.Seek(0, 0)
	me, err := oracle.From(conf)
	if err != nil {
		return err
	}

	assertionMap := me.AsPeer().AsMap()

	assertion := `I assert that this message was signed by me, and
	that it has a nonce and a 'now' field, which together provide good randomness. 
	Furthermore, this message has a 'verifyKey' field you can (and should) use to verify the signature.`
	assertionMap["assertion"] = normalizeText(assertion)
	assertionMap["now"] = fmt.Sprintf("%d", time.Now().UnixNano())

	j, err := json.Marshal(assertionMap)
	if err != nil {
		return err
	}

	pt := me.Compose("assertion", j)

	pt.Headers["pubkey"] = assertionMap["pub"]

	err = pt.Sign(env.Randomness, me.PrivateSigningKey())

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
