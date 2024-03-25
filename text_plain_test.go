package oracle_test

import (
	"crypto/rand"
	"os"
	"slices"
	"testing"

	"github.com/sean9999/go-oracle"
)

var randy = rand.Reader

const SAYING = "The shallow consider liberty a release from all law, from every constraint. The wise man sees in it, on the contrary, the potent Law of Laws."
const POET = "Walt Whitman"
const POEM_PLAIN_LOCATION = "testdata/walt.plain.pem"
const POEM_CRYPT_LOCATION = "testdata/walt.crypt.pem"

func TestPlainText(t *testing.T) {

	oldSkyConfFile, _ := os.Open("testdata/old-sky.conf.toml")
	whiteBirdConfFile, _ := os.Open("testdata/white-bird.conf.toml")

	oldSky, _ := oracle.From(oldSkyConfFile)
	whiteBird, _ := oracle.From(whiteBirdConfFile)

	oldSky.AddPeer(*whiteBird.AsPeer())
	whiteBird.AddPeer(*oldSky.AsPeer())

	whiteBird.Export(whiteBirdConfFile)
	oldSky.Export(oldSkyConfFile)

	plainMsg := oldSky.Compose(POET, []byte(SAYING), whiteBird.AsPeer())
	cryptMsg, err := oldSky.Encrypt(randy, plainMsg, whiteBird.AsPeer())
	if err != nil {
		t.Error(err)
	}

	t.Run("Decrypt", func(t *testing.T) {
		gotMsg, err := whiteBird.Decrypt(cryptMsg, oldSky.AsPeer())
		if err != nil {
			t.Error(err)
		}
		want := []byte(SAYING)
		if !slices.Equal(gotMsg.PlainTextData, want) {
			t.Errorf("got %q but wanted %q", gotMsg.PlainTextData, want)
		}
	})

	t.Run("save as plain PEM", func(t *testing.T) {
		bin, err := plainMsg.MarshalPEM()
		if err != nil {
			t.Error(err)
		}
		err = os.WriteFile(POEM_PLAIN_LOCATION, bin, 0644)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("save as encrypted PEM", func(t *testing.T) {
		bin, err := cryptMsg.MarshalPEM()
		if err != nil {
			t.Error(err)
		}
		err = os.WriteFile(POEM_CRYPT_LOCATION, bin, 0644)
		if err != nil {
			t.Error(err)
		}
	})

}
