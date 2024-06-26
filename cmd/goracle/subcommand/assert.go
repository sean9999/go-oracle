package subcommand

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

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

	assertionMap := me.AsPeer().AsMap()

	assertion := `I assert that this message was signed by me, and that it includes a nonce.`
	assertionMap["assertion"] = normalizeHeredoc(assertion)
	assertionMap["now"] = fmt.Sprintf("%d", time.Now().UnixNano())

	j, err := json.Marshal(assertionMap)
	if err != nil {
		return err
	}

	pt := me.Compose("assertion", j)

	pt.Headers["pubkey"] = assertionMap["pub"]

	err = pt.Sign(rand.New(env.Randomness), me.PrivateSigningKey())

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
