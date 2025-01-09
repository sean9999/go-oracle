package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sean9999/hermeti"
)

func (cmd *Exe) Save(ctx context.Context, env hermeti.Env, args []string) ([]string, error) {
	args, err := cmd.ensureSelf(ctx, env, args)
	if err != nil {
		return nil, err
	}

	cmd.Self.LoadConfig()

	err = cmd.Self.Save(cmd.ConfigFile)
	if err != nil {
		return nil, err
	}

	j, err := json.MarshalIndent(cmd.Self.Config, "", "\t")
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(env.OutStream, "%s\n", j)

	return args, nil
}
