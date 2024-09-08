package subcommand_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

var randy = rand.NewSource(0)

func TestEncryptDecrypt(t *testing.T) {

	tmpFs := fstest.MapFS{
		"plainPem":     nil,
		"encryptedPem": nil,
		"plainIon":     nil,
		"encryptedIon": nil,
	}

	var PLAIN_MSG = "all your base are belong to us."

	t.Run("aged-morning encrypts a message for green-brook", func(t *testing.T) {

		args := strings.Split(fmt.Sprintf("--config=%s encrypt --to=green-brook", AGED_MORNING_CONF), " ")
		env := flargs.NewTestingEnvironment(randy)
		globals, remainingArgs, err := subcommand.ParseGlobals(args)
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

		tmpFs["encryptedPem"] = &fstest.MapFile{
			Data: buf.Bytes(),
		}

	})

	t.Run("green-brook decrypts message from aged-morning", func(t *testing.T) {

		args := strings.Split(fmt.Sprintf("--config=%s decrypt", GREEN_BROOK_CONF), " ")
		env := flargs.NewTestingEnvironment(randy)
		globals, remainingArgs, err := subcommand.ParseGlobals(args)
		if err != nil {
			t.Fatal(err)
		}

		//	decrypt file created in previous step
		env.InputStream.Write(tmpFs["encryptedPem"].Data)
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
