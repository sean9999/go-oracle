package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/sean9999/go-oracle"
)

// type Subcommand struct {
// 	Name       string
// 	Args       []string
// 	Subcommand *Subcommand
// }

var (
	_configFile = flag.String("config", "", "config file")
	_format     = flag.String("format", "pem", "format for encrypted or plain data")
)

func registerGlobalFlags(fset *flag.FlagSet) {
	flag.VisitAll(func(f *flag.Flag) {
		fset.Var(f.Value, f.Name, f.Usage)
	})
}

func ParseArgs() (oracle.Flarg, error) {

	returnFlarg := oracle.Flarg{}

	//flag := flag.NewFlagSet("global flagset", flag.ExitOnError)

	flag.Parse()

	//flag.Parse()
	args := flag.Args()
	cmd, args := args[0], args[1:]

	parseEncrypt := func(largs []string) {
		flag := flag.NewFlagSet("oracle encrypt", flag.ExitOnError)
		flag.String("to", "", "who to encrypt to")
		registerGlobalFlags(flag)
		flag.Parse(largs)
		args = flag.Args()
	}

	parseDecrypt := func(largs []string) {
		flag := flag.NewFlagSet("oracle decrypt", flag.ExitOnError)
		registerGlobalFlags(flag)
		flag.Parse(largs)
		args = flag.Args()
	}

	parseAddPeer := func(largs []string) {
		flag := flag.NewFlagSet("oracle add-peer", flag.ExitOnError)
		peerPtr = flag.String("peer", "", "peer to add (nickname or pubkey)")
		registerGlobalFlags(flag)
		flag.Parse(largs)
		args = flag.Args()
	}

	parseVerify := func(largs []string) {
		flag := flag.NewFlagSet("oracle verify", flag.ExitOnError)
		flag.String("peer", "", "peer who's signature to verify")
		registerGlobalFlags(flag)
		flag.Parse(largs)
		args = flag.Args()
	}

	//fmt.Println("configFile ", *_configFile)
	//fmt.Println("format ", *_format)

	switch *_format {
	case "pem":
	case "ion":
	case "auto":
	default:
		return oracle.NoFlarg, defect{"bad format", "must choose pem or ion or auto", 7, nil}
	}

	if *_configFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			//complain(defect{"No home", "homedir cannot be found", 3, err})
			return oracle.NoFlarg, defect{"No home", "homedir cannot be found", 3, err}
		}
		*_configFile = filepath.Join(home, ".config/goracle/conf.toml")
	}

	//	barf if config file exists or does not exist, depending on context
	switch cmd {
	case "init":
		ErrpotentialConfig := configFileDoesNotExistButCanBeCreated(*_configFile)
		if ErrpotentialConfig != nil {
			return oracle.NoFlarg, defect{"config exists", "config already exists", 11, os.ErrExist}
		}
	default:
		_, ErrExistingConfig := configFileExistsAndIsWellFormed(*_configFile)
		if ErrExistingConfig != nil {
			return oracle.NoFlarg, defect{"bad config", "config doesn't exist or is malformed", 13, os.ErrExist}
		}
	}

	switch cmd {
	case "encrypt":
		parseEncrypt(args)
	case "decrypt":
		parseDecrypt(args)
	case "add-peer":
		parseAddPeer(args)
	case "verify":
		parseVerify(args)
	default:
		flag := flag.NewFlagSet("oracle "+cmd, flag.ExitOnError)
		registerGlobalFlags(flag)
		flag.Parse(args)
		args = flag.Args()
	}

	if cmd == "init" {
		fd, err := os.OpenFile(*_configFile, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return oracle.NoFlarg, defect{"could not create file", "could not create config file", 13, err}
		}
		returnFlarg.ConfigFile = fd
	} else {
		fd, err := os.Open(*_configFile)
		if err != nil {
			return oracle.NoFlarg, defect{"could not open file", "could not open config file", 15, err}
		}
		returnFlarg.ConfigFile = fd
	}

	returnFlarg.Subcommand = cmd
	returnFlarg.Format = *_format
	returnFlarg.InputStream = os.Stdin
	returnFlarg.OutputStream = os.Stdout

	//	under some conditions it's appropriate to have nil values here
	//conf, _ = ConfigFromFileDescriptor(fd)

	//	happy path
	// returnFlarg := oracle.Flarg{
	// 	Subcommand:   cmd,
	// 	Config:       conf,
	// 	ConfigFile:   fd,
	// 	Format:       *_format,
	// 	InputStream:  os.Stdin,
	// 	OutputStream: os.Stdout,
	// }
	return returnFlarg, nil

}
