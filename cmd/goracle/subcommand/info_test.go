package subcommand_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestInfo(t *testing.T) {

	args := strings.Split(fmt.Sprintf("--config=%s info", AGED_MORNING_CONF), " ")

	//	setup
	env := flargs.NewTestingEnvironment(rand.NewSource(0))
	globals, remainingArgs, err := subcommand.ParseGlobals(args)
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

	//	compare to expected
	if !bytes.Equal(got, []byte(AGED_MORNING_PEER)) {
		t.Errorf("%s", got)
		os.WriteFile("../../../testdata/aged-morning.info.json", got, 0644)
	}

}

func TestInfo_badConfig(t *testing.T) {

	var fe *flargs.FlargError

	t.Run("config doesn't exist", func(t *testing.T) {

		args := strings.Split("--config=this/file/doesnt/exist.conf info", " ")

		_, _, err := subcommand.ParseGlobals(args)

		if !errors.As(err, &fe) {
			t.Error("it seems that this is not an FlargError")
		}
	})

	t.Run("config exists but is not valid", func(t *testing.T) {

		args := strings.Split("--config=testdata/invalid_config.txt info", " ")

		_, _, err := subcommand.ParseGlobals(args)

		if !errors.As(err, &fe) {
			t.Error("it seems that this is not an FlargError")
		}
	})

}
