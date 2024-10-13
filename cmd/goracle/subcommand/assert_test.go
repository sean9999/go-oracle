package subcommand_test

import (
	"bufio"
	"bytes"
	"io/fs"
	"strings"
	"testing"

	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestAssertAndVerify(t *testing.T) {

	env := testingEnv(t)

	t.Run("create assertion", func(t *testing.T) {

		args := strings.Split("--config=john.json assert", " ")
		env.Arguments = args

		globals, _, err := subcommand.ParseGlobals(env)
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
		err = env.Filesystem.WriteFile("assertion.pem", buf.Bytes(), fs.ModePerm)
		if err != nil {
			t.Error(err)
		}

	})

	t.Run("verify assertion", func(t *testing.T) {
		args := strings.Split("--config=ringo.json verify", " ")
		//env := flargs.NewTestingEnvironment(randy)
		env.Arguments = args
		//env.Filesystem = tfs

		globals, _, err := subcommand.ParseGlobals(env)
		if err != nil {
			t.Error(err)
		}

		//	open assertion as a file
		fd, err := env.Filesystem.Open("assertion.pem")
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
