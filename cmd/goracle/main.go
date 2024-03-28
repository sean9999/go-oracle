package main

import (
	"fmt"
	"os"
)

func main() {

	flargs, err := ParseArgs(os.Args)
	if err != nil {
		complain(err.(defect))
	}

	fmt.Printf("%#v\n", flargs)

	switch flargs.Subcommand {
	case "encrypt":
		fmt.Println("you chose encrypt and i like that")
	default:
		fmt.Printf("you chose %q and that's just fine", flargs.Subcommand)
	}

}
