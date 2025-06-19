package main

import (
	"context"
	"fmt"

	"github.com/sean9999/hermeti"
	"github.com/sean9999/pear"
)

func main() {

	//	a real CLI uses a real environment
	env := hermeti.RealEnv()
	ctx := context.Background()

	//	capture panics in a pretty stack trace
	defer func() {
		if r := recover(); r != nil {
			pear.NicePanic(env.ErrStream)
		}
	}()

	//	instatiate the object that represents our CLI
	cmd := new(Exe)

	//	wrap it in hermeti.CLI
	cli := &hermeti.CLI{
		Env: env,
		Cmd: cmd.Run,
	}

	//	run it by passing in all command-line args except the first one
	_, err := cli.Run(ctx, env.Args[1:])

	//	if that produced an error, output it
	if err != nil {
		perr, ok := err.(*pear.Pear)
		if ok {
			fmt.Fprintln(env.ErrStream, perr.Dump())
		} else {
			fmt.Fprintln(env.ErrStream, err)
		}
	}

}
