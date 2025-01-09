package main

import (
	"context"
	"fmt"

	"github.com/sean9999/hermeti"
)

func (cmd *Exe) Info(ctx context.Context, env hermeti.Env, args []string) ([]string, error) {

	args, err := cmd.ensureSelf(ctx, env, args)
	if err != nil {
		return nil, err
	}

	for k, v := range cmd.Self.Props.Entries() {
		if k != "pubkey" {
			fmt.Fprintf(env.OutStream, "%s:\t%s\n", k, v)
		}

	}

	//fmt.Fprintf(env.OutStream, "grip:\t%s\n", cmd.Self.AsPeer().Grip())
	fmt.Fprintf(env.OutStream, "pubkey:\t%x\n", cmd.Self.PublicKey().Bytes())
	fmt.Fprintf(env.OutStream, "%s\n", cmd.Self.Art())
	return args, err
}
