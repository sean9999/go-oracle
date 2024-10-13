package subcommand_test

import (
	"bytes"
	"io"
	"io/fs"
	"math/rand"
	"strings"
	"testing"

	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

var randy = rand.NewSource(0)

func TestEncryptDecrypt(t *testing.T) {

	var PLAIN_MSG = "all your base are belong to us."

	env := testingEnv(t)

	t.Run("aged-morning encrypts a message for green-brook", func(t *testing.T) {

		args := strings.Split("--config=john.json encrypt --to=crimson-bird", " ")
		env.Arguments = args

		globals, remainingArgs, err := subcommand.ParseGlobals(env)
		if err != nil {
			t.Fatal(err)
		}

		//	send plain message to stdin
		env.InputStream.Write([]byte(PLAIN_MSG))

		//	encrypt
		err = subcommand.Encrypt(env, globals, remainingArgs)
		if err != nil {
			t.Fatal(err)
		}

		//	save encrypted message to file
		buf := new(bytes.Buffer)
		buf.ReadFrom(env.OutputStream)

		env.Filesystem.WriteFile("msg.pem", buf.Bytes(), fs.ModePerm)

	})

	t.Run("green-brook decrypts message from aged-morning", func(t *testing.T) {

		args := strings.Split("--config=paul.json decrypt", " ")
		env.Arguments = args

		globals, remainingArgs, err := subcommand.ParseGlobals(env)
		if err != nil {
			t.Fatal(err)
		}

		//	cat msg.pem and pipe in stdin
		fd, err := env.Filesystem.Open("msg.pem")
		io.Copy(env.InputStream, fd)

		err = subcommand.Decrypt(env, globals, remainingArgs)
		if err != nil {
			t.Fatal(err)
		}

		//	get decrypted value
		pt := new(oracle.PlainText)
		buf := new(bytes.Buffer)
		buf.ReadFrom(env.OutputStream)
		plainBytes := buf.Bytes()
		err = pt.UnmarshalPEM(plainBytes)
		if err != nil {
			t.Fatal(err)
		}

		//	compare
		if !bytes.Equal(pt.PlainTextData, []byte(PLAIN_MSG)) {
			t.Errorf("expected %q but got %q", PLAIN_MSG, pt.PlainTextData)
		}

	})

}
