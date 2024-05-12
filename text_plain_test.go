package oracle_test

import (
	"os"
	"slices"
	"testing"

	"github.com/sean9999/go-oracle"
)

//var randy = rand.Reader

const SAYING = "The shallow consider liberty a release from all law, from every constraint. The wise man sees in it, on the contrary, the potent Law of Laws."
const POET = "Walt Whitman"
const POEM_PLAIN_LOCATION = "testdata/walt.plain.pem"
const POEM_CRYPT_LOCATION = "testdata/walt.crypt.pem"

func TestPlainText(t *testing.T) {

	agedMorning, _ := oracle.FromFile("testdata/aged-morning.conf.toml")
	greenBrook, _ := oracle.FromFile("testdata/green-brook.conf.toml")

	agedMorning.Deterministic()
	greenBrook.Deterministic()

	agedMorning.AddPeer(greenBrook.AsPeer())
	greenBrook.AddPeer(agedMorning.AsPeer())

	plainMsg := agedMorning.Compose(POET, []byte(SAYING))
	cryptMsg, err := agedMorning.Encrypt(plainMsg, greenBrook.AsPeer())
	if err != nil {
		t.Error(err)
	}

	t.Run("Decrypt", func(t *testing.T) {
		gotMsg, err := greenBrook.Decrypt(cryptMsg)
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
