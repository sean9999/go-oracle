package oracle_test

import (
	"os"
	"testing"

	"github.com/sean9999/go-oracle"
)

const POEM_SIGNED_LOCATION = "testdata/walt.signed.pem"

func TestOracle_Sign(t *testing.T) {

	agedMorning, _ := oracle.FromFile("testdata/aged-morning.conf.toml")
	greenBrook, _ := oracle.FromFile("testdata/green-brook.conf.toml")

	agedMorning.Deterministic()
	greenBrook.Deterministic()

	agedMorning.AddPeer(greenBrook.AsPeer())
	greenBrook.AddPeer(agedMorning.AsPeer())

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

	v := rehydratedMsg.Verify(agedMorning.AsPeer().SigningKey())

	if !v {
		t.Error(v)
	}

}
