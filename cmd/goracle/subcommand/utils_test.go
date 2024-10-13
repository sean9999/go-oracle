package subcommand_test

import (
	"io/fs"
	"math/rand"

	"github.com/sean9999/go-flargs"
	realfs "github.com/sean9999/go-real-fs"
)

const AGED_MORNING_CONF = "../../../testdata/aged-morning.conf.toml"
const GREEN_BROOK_CONF = "../../../testdata/green-brook.conf.toml"
const AGED_MORNING_PEER = `{
	"self": {
		"nick": "aged-morning",
		"pub": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
	},
	"peers": {
		"aged-morning": {
			"nick": "aged-morning",
			"pub": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
		},
		"green-brook": {
			"nick": "green-brook",
			"pub": "044cf4b0be1d933ff30cd78f5510f11322d9f9dfcd138b461662eba1abb1689772453711141335f928e9fb2ae7ec0afe5a7b714a4b762731e515b9b7bfce2c60"
		}
	}
}
`

const GREEN_BROOK_PEERS = `{
  "aged-morning": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
}`

var ringoTxt = []byte(`
{
	"version": "v2.0.0",
	"self": {
		"nick": "silent-firefly",
		"pub": "efebbc6c70051e25ba9a7cb20fa16450ed74b30aad995748ae7e6c9378920a1b4d7a178efb310d6944d4c27d1c88abd5b38ce4a21b22808de7daaab9e76ef5f2",
		"priv": "8bfa2fd6960ce959a5dd32001e990fe39ce604a81e09e1cde44a2daf73e2b6a3c7024a7f9584844bf04219250f8a5bb1f64b41bd95f2afa6a1e60a04b8a634ad"
	},
	"peers": {}
}`)

func testingEnv() *flargs.Environment {

	env := flargs.NewTestingEnvironment(rand.NewSource(0))
	mfs := realfs.TestFS{}
	mfs.WriteFile("ringo.json", ringoTxt, fs.ModeIrregular)
	return env

}
