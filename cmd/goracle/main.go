package main

import (
	"fmt"

	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

//type Xargs map[string]any

//type Command func(ctx context.Context, globalArgs Xargs, localArgs Xargs) ([]byte, error)

func main() {

	var good []byte
	var bad error

	flargs, err := ParseArgs()
	if err != nil {
		complain(err.(defect))
		fmt.Println(err)
	}

	switch flargs.Subcommand {
	case "init":
		good, bad = subcommand.Init(flargs, *_configFile)
	case "export":
		good, bad = subcommand.Export(flargs)
	case "info":
		good, bad = subcommand.Info(flargs)
	case "sign":
		good, bad = subcommand.Sign(flargs)
	case "verify":
		good, bad = subcommand.Verify(flargs)
	}

	//	output
	if len(good) > 0 {
		flargs.OutputStream.Write(good)
	}

	if bad != nil {
		fmt.Println(bad)
	}

}
