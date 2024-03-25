package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/sean9999/go-oracle"
)

func main() {
	o := oracle.New(rand.Reader)

	fd, err := os.Create("testdata/a.conf.toml")

	if err != nil {
		fmt.Println(err)
	} else {
		o.Export(fd)
	}

}
