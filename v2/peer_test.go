package goracle

import (
	"crypto/rand"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeer_UnmarshalJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/wispy-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	prince := new(Principal)
	err = prince.UnmarshalJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "wispy-cloud", prince.Nickname())
	pee := prince.ToPeer()
	assert.Equal(t, pee.Nickname(), prince.Nickname())
	nick1, exists := prince.Props.Get("foo")
	assert.True(t, exists)
	nick2, exists := pee.Props.Get("foo")
	assert.True(t, exists)
	assert.Equal(t, nick1, nick2)
}

func TestPeer_MarshalPEM(t *testing.T) {
	p := NewPrincipal(rand.Reader, map[string]string{"name": "alice"}).ToPeer()
	assert.NotNil(t, p)
	pemfile, err := p.MarshalPEM()
	assert.NoError(t, err)
	assert.Equal(t, "alice", pemfile.Headers["name"])
}

func TestPeer_UnmarshalPEM(t *testing.T) {
	data, err := os.ReadFile("testdata/falling-dawn.pem")
	if err != nil {
		t.Fatal(err)
	}
	prince := new(Principal)
	block, rest := pem.Decode(data)
	assert.Len(t, rest, 0)
	err = prince.UnmarshalPEM(block)
	assert.NoError(t, err)
	assert.Equal(t, "falling-dawn", prince.Nickname())
	pee := prince.ToPeer()
	assert.Equal(t, pee.Nickname(), prince.Nickname())
	nick1, exists := prince.Props.Get("foo")
	assert.True(t, exists)
	nick2, exists := pee.Props.Get("foo")
	assert.True(t, exists)
	assert.Equal(t, nick1, nick2)
}
