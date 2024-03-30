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

const POEM_SIGNED_LOCATION = "testdata/walt.signed.pem"

// func TestOracle_Setup(t *testing.T) {

// 	a_conf := "testdata/a.toml"
// 	b_conf := "testdata/b.toml"

// 	a := oracle.New(rand.Reader)
// 	b := oracle.New(rand.Reader)

// 	a.AddPeer(b.AsPeer())
// 	b.AddPeer(a.AsPeer())

// 	afd, err := os.Create(a_conf)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	bfd, err := os.Create(b_conf)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	a.Export(afd)
// 	b.Export(bfd)

// }

func TestOracle_Sign(t *testing.T) {

	agedMorningConfig, _ := os.Open("testdata/aged-morning.conf.toml")
	greenBrookConfig, _ := os.Open("testdata/green-brook.conf.toml")

	agedMorning, _ := oracle.From(agedMorningConfig)
	greenBrook, _ := oracle.From(greenBrookConfig)

	agedMorning.AddPeer(greenBrook.AsPeer())
	greenBrook.AddPeer(agedMorning.AsPeer())

	// greenBrook.Export(greenBrookConfig)
	// agedMorning.Export(agedMorningConfig)

	plainMsg := agedMorning.Compose(POET, []byte(SAYING))

	err := agedMorning.Sign(plainMsg)
	if err != nil {
		t.Error(err)
	}

	signedMsg := plainMsg

	pem, err := signedMsg.MarshalPEM()
	if err != nil {
		t.Error(err)
	}

	os.WriteFile(POEM_SIGNED_LOCATION, pem, 0644)

	rehydratedMsg := new(oracle.PlainText)
	rehydratedMsg.UnmarshalPEM(pem)

	//v := rehydratedMsg.Verify(ed25519.PublicKey(agedMorning.PrivateSigningKey()))

	//v := agedMorning.Verify(rehydratedMsg, agedMorning.AsPeer())

	v := rehydratedMsg.Verify(agedMorning.AsPeer().SigningKey())

	if !v {
		t.Error(v)
	}

}
