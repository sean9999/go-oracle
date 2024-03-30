package subcommand

import (
	"github.com/sean9999/go-oracle"
)

func Verify(flargs oracle.Flarg) ([]byte, error) {
	// flargs.ConfigFile.Seek(0, 0)
	// me, err := oracle.From(flargs.ConfigFile)
	// if err != nil {
	// 	return nil, err
	// }
	// plainBytes, err := io.ReadAll(flargs.InputStream)
	// if err == nil {
	// 	pt := me.Compose("message", plainBytes)
	// 	err = me.Sign(pt)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return pt.MarshalPEM()
	// } else {
	// 	return nil, err
	// }
}
