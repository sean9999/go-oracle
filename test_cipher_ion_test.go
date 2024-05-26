package oracle_test

import (
	"testing"

	"github.com/sean9999/go-oracle"
)

func TestCipherText_ion(t *testing.T) {

	agedMorning, err := oracle.FromFile("testdata/aged-morning.conf.toml")
	if err != nil {
		t.Error(err)
	}
	agedMorning.Deterministic()

	greenBrook, err := oracle.FromFile("testdata/green-brook.conf.toml")
	if err != nil {
		t.Error(err)
	}
	greenBrook.Deterministic()

	t.Run("Marshal Ion", func(t *testing.T) {
		plainMsg := agedMorning.Compose("A Tale of Two Cities", []byte(PHRASE))
		cryptMsg, err := agedMorning.Encrypt(plainMsg, greenBrook.AsPeer())

		if err != nil {
			t.Error(err)
		}
		ionData, err := cryptMsg.MarshalIon()
		if err != nil {
			t.Error(err)
		}
		testFileSystem[MSG_LOCATION].Data = ionData
		testFileSystem[MSG_LOCATION].Mode = 0644
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Unmarshal Ion", func(t *testing.T) {
		data, err := testFileSystem.ReadFile(MSG_LOCATION)
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
