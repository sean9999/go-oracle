// pemreader reads PEM files from stdin and outputs plain text to stdout
package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/sean9999/go-flargs"
)

type konf struct {
	message []byte
	flargs.StateMachine
}

func (k *konf) Load(env *flargs.Environment) error {
	pemBytes, err := io.ReadAll(env.InputStream)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("nil block")
	}
	k.message = block.Bytes
	return nil
}
func (k *konf) Run(env *flargs.Environment) error {
	_, err := fmt.Fprintf(env.OutputStream, "%s\n", k.message)
	return err
}

func main() {

	k := new(konf)
	env := flargs.NewCLIEnvironment("/")
	cmd := flargs.NewCommand(k, env)
	cmd.LoadAndRun()

}
