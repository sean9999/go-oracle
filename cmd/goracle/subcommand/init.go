package subcommand

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/sean9999/go-oracle"
)

func Init(flarg oracle.Flarg, configFileLocation string) ([]byte, error) {

	//	first create
	_, err := os.OpenFile(configFileLocation, os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}

	//	now grab a handle allowing us to write
	fd, err := os.OpenFile(configFileLocation, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	flarg.ConfigFile = fd

	me := oracle.New(rand.Reader)

	me.Export(fd)

	path := flarg.ConfigFile.Name()
	nick := me.AsPeer().Nickname()

	output := fmt.Sprintf("%q was written to %q", nick, path)

	flarg.OutputStream.Write([]byte(output))

	return []byte(output), nil

}
