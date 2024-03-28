package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/akamensky/argparse"
	"github.com/sean9999/go-oracle"
)

// Flarg represents all the args and flags after normalization and validation
type Flarg struct {
	Subcommand     string
	Config         oracle.Config
	ConfigFile     *os.File
	PreferedFormat string
	InputStream    io.Reader
	OutputStream   io.Writer
}

// The NoFlarg Flarg is used in error conditions
var NoFlarg Flarg

func ParseArgs(args []string) (Flarg, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		//complain(defect{"no home dir", "cannot detect user home dir", 3, err})
		return NoFlarg, defect{"no home dir", "cannot detect user home dir", 3, err}
	}
	flargs := argparse.NewParser("goracle", "a tool for encryptin, decriptin, signing, and veridyting")
	configFileDescriptor := flargs.File("c", "config", os.O_RDWR, 0600, &argparse.Options{Default: filepath.Join(home, ".config/goracle/conf.toml")})
	formatFlag := flargs.Selector("f", "format", []string{"pem", "ion", "auto"}, &argparse.Options{Default: "pem"})
	subCommand := flargs.SelectorPositional([]string{"encrypt", "decrypt", "sign", "verify", "info"}, &argparse.Options{Default: "info"})
	err = flargs.Parse(args)
	if err != nil {
		//complain(defect{"parse error", "failed to parse flags", 1, err})
		//return NoFlarg, defect{"parse error", "failed to parse flags", 1, err}
		return NoFlarg, err
	}

	if argparse.IsNilFile(configFileDescriptor) {
		return NoFlarg, defect{"nil config", "config file descriptor is nil", 2, os.ErrInvalid}
	}
	if len(os.Args) < 2 {
		//complain(defect{"no sub-command", "you must pass a sub-command", 4, nil})
		return NoFlarg, defect{"no sub-command", "you must pass a sub-command", 4, nil}
	}

	//fmt.Println(configFileDescriptor.Name())

	//os.Stdout.ReadFrom(configFileDescriptor)

	conf, err := oracle.ConfigFrom(configFileDescriptor)

	fmt.Println("conf", conf)

	if err != nil {
		fmt.Println(err)

		stat, err := configFileDescriptor.Stat()

		fmt.Println(stat, err)

		return NoFlarg, defect{"bad config", "config file exists but is not parsable", 5, err}
	}

	//	happy path
	f := Flarg{
		Subcommand:     *subCommand,
		Config:         conf,
		ConfigFile:     configFileDescriptor,
		PreferedFormat: *formatFlag,
		InputStream:    os.Stdin,
		OutputStream:   os.Stdout,
	}
	return f, nil

}
