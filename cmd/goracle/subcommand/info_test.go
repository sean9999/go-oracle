package subcommand_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestInfo(t *testing.T) {

	args := strings.Split(fmt.Sprintf("--config=%s info", "ringo.json"), " ")

	env := testingEnv()
	env.Arguments = args

	globals, remainingArgs, err := subcommand.ParseGlobals(env)
	if err != nil {
		t.Error(err)
	}

	//	writes json to env.OutputStream
	err = subcommand.Info(env, globals, remainingArgs)
	if err != nil {
		t.Error(err)
	}

	//	capture that json
	buf := new(bytes.Buffer)
	buf.ReadFrom(env.OutputStream)
	got := buf.Bytes()

	want := ringoTxt

	if !bytes.Equal(want, got) {
		t.Error("wring")
	}

}

func TestInfo_badConfig(t *testing.T) {

	var fe *flargs.FlargError

	t.Run("config doesn't exist", func(t *testing.T) {

		args := strings.Split("--config=this/file/doesnt/exist.conf info", " ")

		env := testingEnv()
		env.Arguments = args

		_, _, err := subcommand.ParseGlobals(env)

		if !errors.As(err, &fe) {
			t.Error("it seems that this is not an FlargError")
		}
	})

	t.Run("config exists but is not valid", func(t *testing.T) {

		args := strings.Split("--config=testdata/invalid_config.txt info", " ")

		env := testingEnv()
		env.Arguments = args

		_, _, err := subcommand.ParseGlobals(env)

		if !errors.As(err, &fe) {
			t.Error("it seems that this is not an FlargError")
		}
	})

}
