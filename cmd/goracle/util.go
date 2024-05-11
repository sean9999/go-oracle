package main

import (
	"fmt"
	"io"
	"os"
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
