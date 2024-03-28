package main

import (
	"fmt"
	"os"
)

type defect struct {
	Name        string
	Description string
	ExitCode    int
	Wraps       error
}

func (def defect) Error() string {
	return def.Description
}

func complain(def defect) {
	fmt.Fprintln(os.Stderr, def.Description)
	os.Exit(def.ExitCode)
}
