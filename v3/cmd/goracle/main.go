package main

import (
	"errors"
	"flag"

	goracle "github.com/sean9999/go-oracle/v3"
	"github.com/sean9999/hermeti"
	"github.com/spf13/afero"
)

type app struct {
	self       *goracle.Principal
	configFile afero.File
}

func (a *app) Init(env hermeti.Env) error {

	var config string
	flargs := flag.NewFlagSet("flargs", flag.ExitOnError)
	flargs.StringVar(&config, "config", "config.json", "your config file")
	flargs.Parse(env.Args)

	return errors.New("not implemented")
}

func (a *app) Run(env hermeti.Env) {

}

func main() {

	cli := hermeti.NewRealCli(new(app))
	cli.Run()

}
