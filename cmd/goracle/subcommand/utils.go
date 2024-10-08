package subcommand

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/sean9999/go-flargs"
	"github.com/sean9999/go-oracle"
)

var DefaultConfigPath = "~/.config/goracle/conf.json"

var ErrNotImplemented *OracleError = NewOracleError("not implemeneted", nil)

type OracleError struct {
	msg   string
	child error
}

func (or *OracleError) Error() string {
	if or.child == nil {
		return or.msg
	} else {
		return fmt.Sprintf("%s: %s", or.msg, or.child)
	}
}

func NewOracleError(msg string, child error) *OracleError {
	or := OracleError{msg, child}
	return &or
}

type ParamSet struct {
	Format string
	Config *os.File
	Me     *oracle.Oracle
	Them   oracle.Peer
}

func normalizeHeredoc(inText string) string {
	r := inText
	r = strings.ReplaceAll(r, "\n", " ")
	r = strings.ReplaceAll(r, "\t", " ")
	r = strings.ReplaceAll(r, "   ", " ")
	r = strings.ReplaceAll(r, "  ", " ")
	r = strings.TrimSpace(r)
	return r
}

func looksLikeHexPubkey(s string) bool {
	//	@todo: make this robust
	return len(s) == 128
}

func looksLikeNickname(s string) bool {
	//	@todo: make this robust too
	return (len(s) > 3 && len(s) < 64)
}

func ParseGlobals(args []string) (*ParamSet, []string, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, flargs.NewFlargError(flargs.ExitCodeGenericError, os.ErrInvalid)
	}
	DefaultConfigPath = strings.Replace(DefaultConfigPath, "~", home, 1)

	configFilePath := DefaultConfigPath
	pset := ParamSet{
		Format: "pem",
	}
	fset := flag.NewFlagSet("globals", flag.ContinueOnError)
	fset.Func("config", "config file", func(s string) error {
		configFilePath = s
		if slices.Contains(args, "init") {
			//	config file must not exist
			//	but it must be a writable path
			_, err := os.Stat(s)
			if err == nil {
				return flargs.NewFlargError(flargs.ExitCodeGenericError, err)
			}
			fd, err := os.OpenFile(s, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return flargs.NewFlargError(flargs.ExitCodeGenericError, err)
			}
			pset.Config = fd
		} else {
			if slices.Contains(args, "verify") || slices.Contains(args, "rekey") {
				//	open for reading and writing
				//	so we can write peers to the file
				fd, err := os.OpenFile(s, os.O_RDWR, 0600)
				if err != nil {
					return flargs.NewFlargError(flargs.ExitCodeGenericError, err)
				}
				//m["config"] = fd
				pset.Config = fd
			} else {
				//	open for reading
				fd, err := os.Open(s)
				if err != nil {
					return flargs.NewFlargError(flargs.ExitCodeGenericError, err)
				}
				//m["config"] = fd
				pset.Config = fd
			}
		}
		return nil
	})
	fset.Func("format", "format to use (pem, ion)", func(s string) error {
		var err error
		switch s {
		case "ion", "pem":
			//m["format"] = s
			pset.Format = s
		default:
			err = flargs.NewFlargError(flargs.ExitCodeGenericError, nil)
		}
		return err
	})

	fset.Parse(args)

	tail := fset.Args()

	switch tail[0] {
	case "echo":
		//	no config needed

	case "init":

		if configFilePath == DefaultConfigPath {
			//	let's output to stdout
			pset.Config = nil
		} else {
			//	set config
			if pset.Config == nil {
				fd, err := os.OpenFile(configFilePath, os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					return &pset, tail, flargs.NewFlargError(flargs.ExitCodeGenericError, err)
				}
				pset.Config = fd
			}
		}

	default:
		//	set config
		if pset.Config == nil {
			fd, err := os.OpenFile(configFilePath, os.O_RDWR, 0600)
			if err != nil {
				return &pset, tail, flargs.NewFlargError(flargs.ExitCodeGenericError, err)
			}
			pset.Config = fd
		}
	}

	// switch tail[0] {
	// case "echo", "init":
	// 	//	no "me" needed
	// default:
	// 	//	we need a me
	// 	me, err := oracle.From(pset.Config)
	// 	if err != nil {
	// 		return &pset, tail, flargs.NewFlargError(flargs.ExitCodeGenericError, err)
	// 	}
	// 	pset.Me = me
	// }

	return &pset, tail, nil

}
