package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

type marg = map[string]any

func Poo() {
	fl := flargs.NewFlargs(func(args []string) (map[string]any, []string, error) {
		m := map[string]any{
			"hello": true,
		}
		return m, nil, nil
	})
	m, _, _ := fl.Parse([]string{"--color=false"})
	orc := oracle.New(rand.Reader)

	fmt.Println(m)
	fmt.Println(orc)

}

func parseGlobals(args []string) (marg, []string, error) {
	fl := flargs.NewFlargs(func(args []string) (marg, []string, error) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, flargs.NewFlargError("could not determine home dir", os.ErrInvalid)
		}
		configFilePath := filepath.Join(home, ".config/goracle/conf.toml")
		m := map[string]any{
			"command": args[0], // should be goracle
			"format":  "pem",
		}
		fset := flag.NewFlagSet("globals", flag.ContinueOnError)
		fset.Func("config", "config file", func(s string) error {
			configFilePath = s
			if slices.Contains(args, "init") {
				//	config file must not exist
				//	but it must be a writable path
				_, err := os.Stat(s)
				if err == nil {
					return flargs.NewFlargError("file exists and init is called", os.ErrExist)
				}
				fd, err := os.OpenFile(s, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					return flargs.NewFlargError("file could not be created", err)
				}
				m["config"] = fd
			} else {
				if slices.Contains(args, "verify") || slices.Contains(args, "rekey") {
					//	open for reading and writing
					fd, err := os.OpenFile(s, os.O_RDWR, 0600)
					if err != nil {
						return flargs.NewFlargError("could not open config", err)
					}
					m["config"] = fd
				} else {
					//	open for reading
					fd, err := os.Open(s)
					if err != nil {
						return flargs.NewFlargError("could not open config", err)
					}
					m["config"] = fd
				}
			}
			return nil
		})
		fset.Func("format", "format to use (pem, ion)", func(s string) error {
			var err error
			switch s {
			case "ion", "pem":
				m["format"] = s
			default:
				err = flargs.NewFlargError("unknown format", nil)
			}
			return err
		})

		fset.Parse(os.Args[1:])

		//	if m["config"] is not set, use default
		_, ok := m["config"]
		if !ok {
			//fd, err := os.Open(configFilePath)
			fd, err := os.OpenFile(configFilePath, os.O_RDWR, 0600)
			if err != nil {
				return m, fset.Args(), err
			}
			m["config"] = fd
		}

		return m, fset.Args(), nil
	})
	return fl.Parse(args)

}
