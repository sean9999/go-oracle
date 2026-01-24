package main

import (
	"errors"
	"fmt"

	"github.com/sean9999/hermeti"
)

var _ hermeti.InitRunner = (*app)(nil)

type app struct{}

func (a *app) Run(env hermeti.Env) {
	fmt.Fprintln(env.OutStream, "hello world")
}

func (a *app) Init(env *hermeti.Env) error {
	if env.Randomness == nil {
		return errors.New("nil randomness")
	}
	return nil
}

func main() {

	hermeti.NewRealCli(new(app)).Run()

}
