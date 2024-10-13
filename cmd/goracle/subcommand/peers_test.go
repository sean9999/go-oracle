package subcommand_test

import (
	"bytes"
	"testing"

	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestPeers(t *testing.T) {

	//args := strings.Split(fmt.Sprintf("--config=paul.json peers", GREEN_BROOK_CONF), " ")

	args := []string{"-config=paul.json", "peers"}

	env := testingEnv(t)
	env.Arguments = args

	//	setup
	globals, _, err := subcommand.ParseGlobals(env)
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
	//got := buf.Bytes()

	//	compare to expected
	t.Error("this test has not been written")
}
