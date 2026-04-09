package oracle

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeer_NickName(t *testing.T) {
	alice := getTestPrincipal(t, "crimson-meadow")
	allie := alice.AsPeer()
	assert.Equal(t, alice.NickName(), allie.NickName())
}

func TestPeer_Save(t *testing.T) {
	allie := getTestPrincipal(t, "crimson-meadow").AsPeer()
	buf := new(bytes.Buffer)
	err := allie.Save(buf)
	assert.NoError(t, err)
	keypairExists := bytes.Contains(buf.Bytes(), []byte("keypair"))
	pubkeyExists := bytes.Contains(buf.Bytes(), []byte("pubkey"))
	assert.False(t, keypairExists)
	assert.True(t, pubkeyExists)
}

func TestPeer_MarshalJSON(t *testing.T) {
	dawn := getTestPrincipal(t, "falling-dawn").AsPeer()
	bin, err := dawn.MarshalPEM()
	assert.NoError(t, err)

	hasNick := bytes.Contains(bin, []byte("nick"))
	hasNickName := bytes.Contains(bin, []byte("falling-dawn"))
	assert.True(t, hasNick)
	assert.True(t, hasNickName)

	err = os.WriteFile("testdata/falling-dawn.peer.pem", bin, 0600)
	assert.NoError(t, err)
}

func TestPeer_UnmarshalPEM(t *testing.T) {
	bin, err := os.ReadFile("testdata/falling-dawn.peer.pem")
	assert.NoError(t, err)
	peer := new(Peer)
	err = peer.UnmarshalPEM(bin)
	assert.NoError(t, err)
	assert.Equal(t, "falling-dawn", peer.NickName())

	//	since this is a derived property, it should not explicitly exist as a Prop
	assert.Equal(t, "", peer.Props["nick"])
}
