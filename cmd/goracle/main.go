package main

import (
	"os"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func main() {

	env := flargs.NewCLIEnvironment()
	globals, remainingArgs, err := parseGlobals(os.Args)
	if err != nil {
		complain("could not parse globals", 5, nil, env.ErrorStream)
	}

	if len(remainingArgs) == 0 {
		remainingArgs = append(remainingArgs, "info")
	}
	switch remainingArgs[0] {
	case "info":
		err = subcommand.Info(env, globals, remainingArgs)
		if err != nil {
			complain("subcommand info", 7, err, env.ErrorStream)
		}
	case "init":
		err = subcommand.Init(env, globals)
		if err != nil {
			complain("subcommand init", 7, err, env.ErrorStream)
		}
	case "assert":
		err = subcommand.Assert(env, globals)
		if err != nil {
			complain("subcommand assert", 7, err, env.ErrorStream)
		}
	case "echo":
		err = subcommand.Echo(env)
		if err != nil {
			complain("subcommand echo", 7, err, env.ErrorStream)
		}
	case "sign":
		err = subcommand.Sign(env, globals)
		if err != nil {
			complain("subcommand sign", 7, err, env.ErrorStream)
		}
	case "verify", "add-peer":
		err = subcommand.Verify(env, globals)
		if err != nil {
			complain("subcommand verify / add-peer", 7, err, env.ErrorStream)
		}
	case "peers":
		err = subcommand.Peers(env, globals)
		if err != nil {
			complain("subcommand peers", 7, err, env.ErrorStream)
		}
	case "encrypt":
		err = subcommand.Encrypt(env, globals, remainingArgs)
		if err != nil {
			complain("subcommand encrypt", 7, err, env.ErrorStream)
		}
	case "decrypt":
		err = subcommand.Decrypt(env, globals, remainingArgs)
		if err != nil {
			complain("subcommand decrypt", 7, err, env.ErrorStream)
		}
	default:
		complain("unsupported subcommand", 3, nil, env.ErrorStream)
	}
}
