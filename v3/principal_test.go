package oracle

import (
	"bytes"
	"github.com/sean9999/go-oracle/v3/delphi"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPrincipal(t *testing.T) {

	t.Run("happy path", func(t *testing.T) {
		alice := NewPrincipal(fakeRand(11))
		nick := alice.NickName()
		assert.Equal(t, "restless-mountain", nick)
		assert.Panics(t, func() {
			eve := new(Principal)
			_ = eve.NickName()
		})
	})

	t.Run("zero key should panic", func(t *testing.T) {
		assert.Panics(t, func() {
			eve := NewPrincipal(fakeRand(0))
			_ = eve.NickName()
		})
	})
}

func TestLoadPrincipal(t *testing.T) {
	alice := getTestPrincipal(t, "alice")
	alice.Props["favourite colour"] = "blue"
	nick := alice.NickName()
	assert.Equal(t, "falling-dawn", nick)
	assert.Equal(t, "blue", alice.Props["favourite colour"])
}

func TestPrincipal_AsPeer(t *testing.T) {
	alice := getTestPrincipal(t, "falling-dawn")
	peer := alice.AsPeer()
	buf := new(bytes.Buffer)
	err := peer.Save(buf)
	assert.NoError(t, err)
}

func TestPrincipal_MustBeValid(t *testing.T) {
	assert.Panics(t, func() {
		malory := NewPrincipal(fakeRand(1))
		malory.Props = nil
		malory.MustBeValid()
	})
	assert.Panics(t, func() {
		malory := NewPrincipal(fakeRand(1))
		malory.KeyPair[0] = delphi.Key{} // the existence of a zero-key should cause panic
		malory.MustBeValid()
	})
	assert.Panics(t, func() {
		malory := NewPrincipal(fakeRand(1))
		malory.KeyPair[1] = delphi.Key{} // the existence of a zero-key should cause panic
		malory.MustBeValid()
	})
}

func TestPrincipal_Save(t *testing.T) {
	alice := getTestPrincipal(t, "alice")
	alice.Props["favourite band"] = "Nirvana"
	buf := new(bytes.Buffer)
	err := alice.SaveJSON(buf)
	assert.NoError(t, err)
	keyExists := bytes.Contains(buf.Bytes(), []byte("favourite band"))
	valExists := bytes.Contains(buf.Bytes(), []byte("Nirvana"))
	assert.True(t, keyExists)
	assert.True(t, valExists)
}

func TestPrincipal_SavePeers(t *testing.T) {
	alice := NewPrincipal(fakeRand(1))
	bob := NewPrincipal(fakeRand(3)).AsPeer()
	carl := NewPrincipal(fakeRand(4)).AsPeer()
	dan := NewPrincipal(fakeRand(5)).AsPeer()
	alice.AddPeer(bob)
	alice.AddPeer(carl)
	alice.AddPeer(dan)
	assert.True(t, alice.HasPeer(bob.PublicKey))
	someKey := delphi.NewKey(fakeRand(7))
	assert.False(t, alice.HasPeer(delphi.PublicKey(someKey)))
	assert.Len(t, alice.Peers, 3)
}

func TestPrincipal_MarshalPEM(t *testing.T) {

	t.Run("plain jane", func(t *testing.T) {
		dawn := getTestPrincipal(t, "falling-dawn")
		bin, err := dawn.MarshalPEM()
		assert.NoError(t, err)
		isPriv := bytes.Contains(bin, []byte("PRIVATE KEY"))
		hasNick := bytes.Contains(bin, []byte("falling-dawn"))
		assert.True(t, isPriv)
		assert.True(t, hasNick)
	})

	t.Run("fancy nancy create", func(t *testing.T) {
		prince := NewPrincipal(fakeRand(5))
		prince.Props["favourite colour"] = "blue"
		prince.Props["favourite band"] = "Nirvana"
		nick := prince.NickName()
		assert.Equal(t, "damp-night", nick)
		bin, err := prince.MarshalPEM()
		assert.NoError(t, err)
		hasBand := bytes.Contains(bin, []byte("favourite band"))
		hasNirvana := bytes.Contains(bin, []byte("Nirvana"))
		hasBlue := bytes.Contains(bin, []byte("blue"))
		assert.True(t, hasBand)
		assert.True(t, hasNirvana)
		assert.True(t, hasBlue)
	})

	t.Run("fancy nancy read", func(t *testing.T) {
		bin, err := os.ReadFile("testdata/damp-night.principal.pem")
		assert.NoError(t, err)
		dampNight := new(Principal)
		err = dampNight.UnmarshalPEM(bin)
		assert.NoError(t, err)
		assert.Equal(t, "damp-night", dampNight.NickName())
		assert.Equal(t, "Nirvana", dampNight.Props["favourite band"])
		jack := NewPrincipal(fakeRand(5)).AsPeer()
		assert.Len(t, dampNight.Peers, 0)
		dampNight.AddPeer(jack)
		assert.Len(t, dampNight.Peers, 1)
	})
}

func TestPrincipal_UnmarshalPEM(t *testing.T) {
	bin, err := os.ReadFile("testdata/falling-dawn.principal.pem")
	assert.NoError(t, err)
	prince := new(Principal)
	err = prince.UnmarshalPEM(bin)
	assert.NoError(t, err)
	assert.Equal(t, "falling-dawn", prince.NickName())
	assert.Len(t, prince.Peers, 0)
	jack := NewPrincipal(fakeRand(9)).AsPeer()
	prince.AddPeer(jack)
	assert.Len(t, prince.Peers, 1)
}
