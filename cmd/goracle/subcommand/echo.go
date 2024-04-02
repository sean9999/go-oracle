package subcommand

import (
	"fmt"
	"io"

	"github.com/sean9999/go-flargs"
)

// echo takes what it's given on stdIn outputs it unchanged to stdOut.
// @note: this may not be useful in the final product, but it's helpful for debugging
func Echo(env *flargs.Environment) error {

	_, err := io.Copy(env.OutputStream, env.InputStream)
	if err != nil {
		return NewOracleError("can't copy stream", err)
	}

	//msg := fmt.Sprintf("%d bytes written", i)
	fmt.Fprintln(env.OutputStream)
	//fmt.Fprintln(env.OutputStream, msg)

	return nil
}
