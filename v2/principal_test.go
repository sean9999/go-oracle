package goracle

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrincipal_Unmarshal(t *testing.T) {
	data, err := os.ReadFile("testdata/wispy-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	p := new(Principal)
	err = p.UnmarshalJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "wispy-cloud", p.Nickname())
}

func TestNewPrincipal(t *testing.T) {
	p := NewPrincipal(fakeRand(11), map[string]string{"foo": "bar"})
	assert.Equal(t, "falling-dawn", p.Nickname())
	foo, ok := p.Props.Get("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", foo)
	nofoo, ok := p.Props.Get("_nofoo")
	assert.False(t, ok)
	assert.Len(t, nofoo, 0)
}

func TestAssert(t *testing.T) {
	p := NewPrincipal(fakeRand(11), map[string]string{"foo": "bar"})
	msg, err := p.Assert(fakeRand(11))
	assert.NoError(t, err)
	assert.Greater(t, len(msg.Sig), 0)
	ok := msg.Verify()
	assert.True(t, ok)
}

func TestPrincipal_Save(t *testing.T) {
	alice := NewPrincipal(fakeRand(11), map[string]string{"name": "alice"})
	assert.NotNil(t, alice)
	alice.Props.Set("bing", "bat")
	bob := NewPrincipal(fakeRand(12), map[string]string{"name": "bob"}).ToPeer()
	carrie := NewPrincipal(fakeRand(13), map[string]string{"name": "carrie"}).ToPeer()
	alice.Peers.Set("bob", bob)
	alice.Peers.Set("carrie", carrie)
	alice.Peers.Delete("bob")
	buf := bytes.NewBuffer(nil)
	err := alice.Save(buf)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "carrie")
}
