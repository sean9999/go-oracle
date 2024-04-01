package subcommand

import (
	"fmt"
	"io"

	"github.com/sean9999/go-flargs"
)

func Echo(env *flargs.Environment) error {

	i, err := io.Copy(env.OutputStream, env.InputStream)
	if err != nil {
		return err
	}

	msg := fmt.Sprintf("%d bytes written", i)

	fmt.Fprintln(env.OutputStream)
	fmt.Fprintln(env.OutputStream, msg)

	return nil
}
