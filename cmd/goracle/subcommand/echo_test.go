package subcommand_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle/cmd/goracle/subcommand"
)

func TestEcho(t *testing.T) {

	env := flargs.NewTestingEnvironment()

	//	send in input
	input := []byte("all your base are belong to us.")
	env.InputStream.Write(input)

	err := subcommand.Echo(env)
	if err != nil {
		t.Error(err)
	}

	//	get output
	buf := new(bytes.Buffer)
	buf.ReadFrom(env.OutputStream)

	//	normalize, because output appends a newline
	got := fmt.Sprintln(strings.TrimSpace(buf.String()))
	want := fmt.Sprintln(strings.TrimSpace(string(input)))

	if want != got {
		t.Errorf("wanted %q but got %q", want, got)
	}

}
