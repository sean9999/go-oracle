package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	gork "github.com/sean9999/go-oracle/v2"
	"github.com/sean9999/hermeti"
	"github.com/sean9999/pear"
	"github.com/spf13/afero"
)

// an OracleCLIError is an error with an exit code
type OracleCLIError struct {
	Msg      string
	ExitCode int
	Child    error
}

func (orr *OracleCLIError) Error() string {
	if orr.Child == nil {
		return orr.Msg
	} else {
		return fmt.Sprintf("%s: %s", orr.Msg, orr.Child)
	}
}

func complain(msg string, exitCode int, child error, stream io.Writer) {
	err := &OracleCLIError{msg, exitCode, child}
	fmt.Fprintln(stream, err)
	os.Exit(exitCode)
}

// Exe is the execution of a command, including all necessary state
type Exe struct {
	Verbosity  uint
	DieNow     bool
	Self       *gork.Principal
	ConfigFile afero.File
}

// Run sets the whole thing in motion and contains the entire execution lifecycle
func (exe *Exe) Run(ctx context.Context, env hermeti.Env, args []string) ([]string, error) {
	args, err := exe.bootstrap(ctx, env, args)
	if err != nil {
		return args, err
	}

	//	if no subcommand is specified, "info" is implied
	subcmd := "info"

	if len(args) > 0 {
		subcmd = args[0]
		args = args[1:]
	}

	subcommands := map[string]hermeti.Command{
		"info": exe.Info,
		"init": exe.Init,
		"save": exe.Save,
	}

	fn, exists := subcommands[subcmd]

	if !exists {
		err := pear.Errorf("unsupported command: %q", subcmd)
		return args, err
	}

	return fn(ctx, env, args)

}

// parse global values early in execution
func (cmd *Exe) bootstrap(_ context.Context, _ hermeti.Env, args []string) ([]string, error) {

	gset := flag.NewFlagSet("global", flag.ContinueOnError)
	verbosity := gset.Uint("verbosity", 0, "verbosity level")
	dienow := gset.Bool("die", false, "should we just die?")
	gset.Parse(args)

	cmd.Verbosity = *verbosity
	cmd.DieNow = *dienow

	if *dienow {
		return nil, pear.New("we must die now")
	}

	args = gset.Args()

	return args, nil

}

// ensureSelf ensures the presence of a gork.Principal by checking current state and/or parsing flags
func (cmd *Exe) ensureSelf(_ context.Context, env hermeti.Env, args []string) ([]string, error) {

	if cmd.Self != nil {
		return args, nil
	}

	fset := flag.NewFlagSet("selfer", flag.ContinueOnError)
	conf := new(string)
	priv := new(string)
	fset.StringVar(conf, "config", "~/.gork/config.json", "config file location")
	fset.StringVar(priv, "priv", "_some_priv.pem", "private key location")
	fset.Parse(args)

	//	the lack of a well-formed pem file is fatal
	pemFile, err := env.Filesystem.Open(*priv)
	if err != nil {
		return args, pear.Errorf("could not find pem file: %w", err)
	}

	pemBytes, err := io.ReadAll(pemFile)
	if err != nil {
		return args, pear.Errorf("could not read pem file: %w", err)
	}

	p := new(gork.Principal)

	p.WithRand(env.Randomness)

	err = p.UnmarshalPEM(pemBytes)
	if err != nil {
		return args, pear.Errorf("could not create principal: %w", err)
	}
	cmd.Self = p

	//	the lack of a config file is not an error
	confFile, err := env.Filesystem.OpenFile(*conf, os.O_RDWR, 0644)
	if err == nil {
		err = p.WithConfigFile(confFile)
		if err != nil {
			return nil, err
		}
		cmd.ConfigFile = confFile
	}

	return fset.Args(), nil

}
