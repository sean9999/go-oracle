package oracle

import (
	"testing"
)

type deterministicRandomness uint8

func (b deterministicRandomness) Read(p []byte) (int, error) {
	for i := range len(p) {
		p[i] = byte(b)
	}
	return len(p), nil
}

var bobRand = deterministicRandomness(5)   // little water
var sallyRand = deterministicRandomness(4) // spring pond
var aliceRand = deterministicRandomness(3) // empty fire

func TestSave(t *testing.T) {
	bob, err := FromFile("testdata/little-water.json")
	if err != nil {
		t.Error(err)
	}

	bobNick := "little-water"
	if bob.Nickname() != bobNick {
		t.Errorf("wanted %q but got %q", bobNick, bob.Nickname())
	}

	sally := New(sallyRand)
	sallyNick := "spring-pond"
	if sally.Nickname() != sallyNick {
		t.Errorf("wanted %q but got %q", sallyNick, sally.Nickname())
	}

	alice := New(aliceRand)
	aliceNick := "empty-fire"
	if alice.Nickname() != aliceNick {
		t.Errorf("wanted %q but got %q", aliceNick, alice.Nickname())
	}

	// fd, err := os.OpenFile("testdata/empty-fire.json", os.O_CREATE|os.O_RDWR, 0600)
	// if err != nil {
	// 	t.Error(err)
	// }

	// err = alice.Export(fd, true)
	// if err != nil {
	// 	t.Error(err)
	// }

	aliceConf := alice.Config()
	if aliceConf.Self.Nickname != aliceNick {
		t.Errorf("expected %q but got %q", aliceNick, aliceConf.Self.Nickname)
	}

}
