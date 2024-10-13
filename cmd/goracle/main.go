package main

import (
	"fmt"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func main() {

	env := flargs.NewCLIEnvironment("/")
	//globals, remainingArgs, err := subcommand.ParseGlobals(os.Args[1:])

	globals, remainingArgs, err := subcommand.ParseGlobals(env)

	if err != nil {
		complain("could not parse globals", 5, nil, env.ErrorStream)
	}

	if len(remainingArgs) == 0 {
		remainingArgs = append(remainingArgs, "info")
	}
	switch remainingArgs[0] {

	case "info":
		err = subcommand.Info(env, globals, remainingArgs)
	case "init":
		err = subcommand.Init(env, globals)
	case "assert":
		err = subcommand.Assert(env, *globals)
	case "echo":
		err = subcommand.Echo(env)
	case "sign":
		err = subcommand.Sign(env, globals)
	case "verify", "add-peer":
		err = subcommand.Verify(env, globals)
	case "peers":
		err = subcommand.Peers(env, globals)
	case "encrypt":
		err = subcommand.Encrypt(env, globals, remainingArgs)
	case "decrypt":
		err = subcommand.Decrypt(env, globals, remainingArgs)

	default:
		complain("unsupported subcommand", 3, nil, env.ErrorStream)
	}
	if err != nil {
		complain(fmt.Sprintf("subcommand %s", remainingArgs[0]), 7, err, env.ErrorStream)
	}

}
