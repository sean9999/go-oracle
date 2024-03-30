package subcommand

import "github.com/sean9999/go-oracle"

func Export(flarg oracle.Flarg) ([]byte, error) {

	me, err := oracle.From(flarg.ConfigFile)
	if err != nil {
		return nil, err
	}
	p := me.AsPeer()

	return p.MarshalJSON()

}
