package oracle_test

import (
	"os"
	"testing"

	"github.com/sean9999/go-oracle"
)

// var randy = rand.Reader

// const SAYING = "The shallow consider liberty a release from all law, from every constraint. The wise man sees in it, on the contrary, the potent Law of Laws."
// const POET = "Walt Whitman"
// const POEM_PLAIN_LOCATION = "testdata/walt.plain.pem"
// const POEM_CRYPT_LOCATION = "testdata/walt.crypt.pem"

func TestOracle_Sign(t *testing.T) {

	oldSkyConfFile, _ := os.Open("testdata/old-sky.conf.toml")
	whiteBirdConfFile, _ := os.Open("testdata/white-bird.conf.toml")

	oldSky, _ := oracle.From(oldSkyConfFile)
	whiteBird, _ := oracle.From(whiteBirdConfFile)

	oldSky.AddPeer(*whiteBird.AsPeer())
	whiteBird.AddPeer(*oldSky.AsPeer())

	whiteBird.Export(whiteBirdConfFile)
	oldSky.Export(oldSkyConfFile)

	plainMsg := oldSky.Compose(POET, []byte(SAYING), whiteBird.AsPeer())

	err := oldSky.Sign(plainMsg)

	if err != nil {
		t.Error(err)
	}

	v := whiteBird.Verify(plainMsg, oldSky.AsPeer())

	if !v {
		t.Error(v)
	}

}
