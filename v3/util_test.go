package oracle

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeRand byte

func (f fakeRand) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func generatePrincipal(t testing.TB, seed int) *Principal {
	t.Helper()
	prince := NewPrincipal(fakeRand(seed))
	buf := new(bytes.Buffer)
	err := prince.SaveJSON(buf)
	assert.NoError(t, err)
	name := prince.NickName()
	err = os.WriteFile("testdata/"+name+".priv.json", buf.Bytes(), 0666)
	assert.NoError(t, err)
	return prince
}

func getTestPrincipal(t testing.TB, name string) *Principal {
	t.Helper()
	f, err := os.Open("testdata/" + name + ".priv.json")
	assert.NoError(t, err)
	p, err := LoadJSON(f)
	assert.NoError(t, err)
	return p
}

func savePrincipal(t testing.TB, alice *Principal) {
	t.Helper()
	buf := new(bytes.Buffer)
	err := alice.SaveJSON(buf)
	assert.NoError(t, err)
	nick := alice.NickName()
	err = os.WriteFile("testdata/"+nick+".priv.json", buf.Bytes(), 0666)
	assert.NoError(t, err)
}
