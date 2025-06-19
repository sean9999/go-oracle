package main

import (
	"bufio"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"

	"github.com/sean9999/go-delphi"
	goracle "github.com/sean9999/go-oracle/v2"
	"github.com/sean9999/hermeti"
)

type app struct {
	self *goracle.Principal
	pems []*pem.Block
}

func fillPems(pems []*pem.Block, stream io.Reader) ([]*pem.Block, error) {
	remaingBytes, err := io.ReadAll(stream)
	if err != nil {
		return pems, err
	}
	for {
		block, rest := pem.Decode(remaingBytes)
		if block == nil {
			break
		}
		pems = append(pems, block)
		remaingBytes = rest
	}
	return pems, nil
}

func stdinHasSomething(r io.Reader) (bool, error) {
	fd, ok := r.(fs.File)
	if !ok {
		//	if this is not a file, peek and check that least 1 byte is available
		b := bufio.NewReaderSize(r, 1)
		_, err := b.Peek(1)
		return (err != nil), err
	}
	//	if this is a file, stat to get its size
	info, err := fd.Stat()
	if err != nil {
		return false, err
	}
	return (info.Size() > 0), nil
}

func (a *app) Init(env hermeti.Env) error {
	has, _ := stdinHasSomething(env.InStream)
	if has {
		pems, err := fillPems(a.pems, env.InStream)
		if err != nil {
			return err
		}
		a.pems = pems
	}
	return nil
}

func (a *app) Run(env hermeti.Env) {

	if len(a.pems) == 0 {
		//	new principal
		p := goracle.NewPrincipal(rand.Reader, nil)
		block, err := p.MarshalPEM()
		if err != nil {
			fmt.Fprintln(env.ErrStream, err)
			return
		} else {
			fmt.Fprintf(env.OutStream, "%s\n", pem.EncodeToMemory(block))
			return
		}
	}

	if len(a.pems) == 1 {
		if a.pems[0].Type == string(delphi.Privkey) {
			fmt.Fprintf(env.OutStream, "%s\n", pem.EncodeToMemory(a.pems[0]))
			return
		}
	}

	fmt.Fprintf(env.OutStream, "we have %d pems\n", len(a.pems))
}

func main() {

	app := new(app)
	cli := hermeti.NewRealCli(app)
	cli.Run()

}
