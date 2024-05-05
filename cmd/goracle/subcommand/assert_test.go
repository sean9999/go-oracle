package subcommand_test

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestAssertAndVerify(t *testing.T) {

	tmpFs := fstest.MapFS{
		"assertion": nil,
	}

	t.Run("create assertion", func(t *testing.T) {

		args := strings.Split(fmt.Sprintf("--config=%s assert", AGED_MORNING_CONF), " ")

		//	setup
		env := flargs.NewTestingEnvironment(randy)
		globals, _, err := subcommand.ParseGlobals(args)
		if err != nil {
			t.Error(err)
		}
		//	create assertion
		err = subcommand.Assert(env, *globals)
		if err != nil {
			t.Error(err)
		}
		//	capture assertion
		buf := new(bytes.Buffer)
		buf.ReadFrom(env.OutputStream)

		//	save to "file"
		tmpFs["assertion"] = &fstest.MapFile{
			Data: buf.Bytes(),
		}

	})

	t.Run("verify assertion", func(t *testing.T) {
		args := strings.Split(fmt.Sprintf("--config=%s verify", AGED_MORNING_CONF), " ")

		//	setup
		env := flargs.NewTestingEnvironment(randy)
		globals, _, err := subcommand.ParseGlobals(args)
		if err != nil {
			t.Error(err)
		}

		//	open assertion as a file
		fd, err := tmpFs.Open("assertion")
		if err != nil {
			t.Error(err)
		}

		//	stream to stdin
		b := bufio.NewReader(fd)
		b.WriteTo(env.InputStream)

		//	verify
		err = subcommand.Verify(env, globals)
		if err != nil {
			t.Error(err)
		}

	})

}
