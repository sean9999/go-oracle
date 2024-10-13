package subcommand_test

import (
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/sean9999/go-flargs"
	realfs "github.com/sean9999/go-real-fs"
)

var ringoTxt = []byte(`
{
	"version": "v2.0.0",
	"self": {
		"nick": "silent-firefly",
		"pub": "efebbc6c70051e25ba9a7cb20fa16450ed74b30aad995748ae7e6c9378920a1b4d7a178efb310d6944d4c27d1c88abd5b38ce4a21b22808de7daaab9e76ef5f2",
		"priv": "8bfa2fd6960ce959a5dd32001e990fe39ce604a81e09e1cde44a2daf73e2b6a3c7024a7f9584844bf04219250f8a5bb1f64b41bd95f2afa6a1e60a04b8a634ad"
	},
	"peers": {}
}`)

func testingEnv(t *testing.T) *flargs.Environment {

	t.Helper()

	env := flargs.NewTestingEnvironment(randy)
	tfs := realfs.NewTestFs()
	env.Filesystem = tfs

	beatles := []string{"john", "paul", "george", "ringo"}
	for _, beatle := range beatles {
		contents, err := os.ReadFile(fmt.Sprintf("../../../testdata/%s.json", beatle))
		if err != nil {
			t.Fatal(err)
		}
		tfs.WriteFile(fmt.Sprintf("%s.json", beatle), contents, fs.ModePerm)
	}
	return env
}
