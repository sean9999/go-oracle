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

	brokenWind, err := oracle.FromFile("testdata/broken-wind.config.toml")
	if err != nil {
		t.Error(err)
	}
	muddyMoon, err := oracle.FromFile("testdata/muddy-moon.config.toml")
	if err != nil {
		t.Error(err)
	}

	t.Run("MarshalIon", func(t *testing.T) {
		plainMsg := brokenWind.Compose("A Tale of Two Cities", []byte(PHRASE), muddyMoon.AsPeer())
		//cryptMsg, err := plainMsg.Encrypt(randy)

		cryptMsg, err := brokenWind.Encrypt(randy, plainMsg, muddyMoon.AsPeer())

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
		plainMsg, err := muddyMoon.Decrypt(encryptedMsg, brokenWind.AsPeer())
		if err != nil {
			t.Error(err)
		}
		if string(plainMsg.PlainTextData) != PHRASE {
			t.Errorf("PLAIN TEXT: %s", plainMsg.PlainTextData)
		}
	})

}
