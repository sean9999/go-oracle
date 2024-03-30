package oracle_test

import (
	"os"
	"testing"

	"github.com/sean9999/go-oracle"
)

const PHRASE = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of light, it was the season of darkness, it was the spring of hope, it was the winter of despair."
const MSG_LOCATION = "testdata/tale_of_two_cities.ion"

var encryptedMsg = new(oracle.CipherText)

func TestCipherText(t *testing.T) {

	agedMorning, err := oracle.FromFile("testdata/aged-morning.conf.toml")
	if err != nil {
		t.Error(err)
	}
	greenBrook, err := oracle.FromFile("testdata/green-brook.conf.toml")
	if err != nil {
		t.Error(err)
	}

	t.Run("MarshalIon", func(t *testing.T) {
		plainMsg := agedMorning.Compose("A Tale of Two Cities", []byte(PHRASE))
		//cryptMsg, err := plainMsg.Encrypt(randy)

		cryptMsg, err := agedMorning.Encrypt(plainMsg, greenBrook.AsPeer())

		if err != nil {
			t.Error(err)
		}
		ionData, err := cryptMsg.MarshalIon()
		if err != nil {
			t.Error(err)
		}
		err = os.WriteFile(MSG_LOCATION, ionData, 0644)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("UnmarshalIon", func(t *testing.T) {
		data, err := os.ReadFile(MSG_LOCATION)
		if err != nil {
			t.Error(err)
		}
		//encryptedMsg = new(oracle.CipherText)
		err = encryptedMsg.UnmarshalIon(data)
		if err != nil {
			t.Error(err)
		}

		subject, exists := encryptedMsg.Headers["subject"]
		if !exists {
			t.Error("subject does not exist in Headers")
		}
		if subject != "A Tale of Two Cities" {
			t.Errorf("expected subject to be %q but got %q", "A Tale of Two Cities", encryptedMsg.Headers["subject"])
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		plainMsg, err := greenBrook.Decrypt(encryptedMsg)
		if err != nil {
			t.Error(err)
		}
		if string(plainMsg.PlainTextData) != PHRASE {
			t.Errorf("PLAIN TEXT: %s", plainMsg.PlainTextData)
		}
	})

}
