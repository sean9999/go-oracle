package oracle_test

import (
	"crypto/rand"
	"testing"

	"github.com/sean9999/go-oracle"
)

var randy = rand.Reader

func TestPlainText(t *testing.T) {

	brokenWind, err := oracle.FromFile("testdata/broken-wind.config.toml")
	if err != nil {
		t.Error(err)
	}
	muddyMoon, err := oracle.FromFile("testdata/muddy-moon.config.toml")
	if err != nil {
		t.Error(err)
	}

	plainMsg := brokenWind.Compose("hello", []byte("world"), muddyMoon.AsPeer())
	cryptMsg, err := plainMsg.Encrypt(randy)
	if err != nil {
		t.Error(err)
	}

	gotMsg, err := muddyMoon.Decrypt(cryptMsg, brokenWind.AsPeer())
	if err != nil {
		t.Error(err)
	}
	t.Error(string(gotMsg.PlainTextData))

}
