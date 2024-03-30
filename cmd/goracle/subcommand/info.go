package subcommand

import "github.com/sean9999/go-oracle"

func Info(flargs oracle.Flarg) ([]byte, error) {

	flargs.ConfigFile.Seek(0, 0)
	me, err := oracle.From(flargs.ConfigFile)
	if err != nil {
		return nil, err
	}
	return me.AsPeer().MarshalJSON()

}
