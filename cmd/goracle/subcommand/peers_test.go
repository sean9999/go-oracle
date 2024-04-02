package subcommand_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestPeers(t *testing.T) {

	args := strings.Split(fmt.Sprintf("--config=%s peers", GREEN_BROOK_CONF), " ")

	//	setup
	env := flargs.NewTestingEnvironment()
	globals, _, err := subcommand.ParseGlobals(args)
	if err != nil {
		t.Error(err)
	}

	//	writes json to env.OutputStream
	err = subcommand.Peers(env, globals)
	if err != nil {
		t.Error(err)
	}

	//	capture that json
	buf := new(bytes.Buffer)
	buf.ReadFrom(env.OutputStream)
	got := buf.Bytes()

	//	compare to expected
	if !bytes.Equal(got, []byte(GREEN_BROOK_PEERS)) {
		t.Errorf("%s", got)
	}

}
