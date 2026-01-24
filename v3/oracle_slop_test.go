package oracle

import (
	"encoding/pem"
	"testing"

	"github.com/sean9999/go-oracle/v3/delphi"
	"github.com/stretchr/testify/assert"
)

func TestPeer_UnmarshalPEM_Failures(t *testing.T) {
	p := &Peer{}

	// 1. Bad PEM decode
	err := p.UnmarshalPEM([]byte("bad"))
	if err == nil {
		t.Error("expected error on bad pem")
	}

	// 2. Wrong Type
	block := &pem.Block{Type: "WRONG", Bytes: []byte{}}
	pemBytes := pem.EncodeToMemory(block)
	err = p.UnmarshalPEM(pemBytes)
	if err == nil {
		t.Error("expected error on wrong type")
	}

	// 3. Bad Key Bytes
	block = &pem.Block{Type: "ORACLE PEER", Bytes: []byte("bad key")}
	pemBytes = pem.EncodeToMemory(block)
	err = p.UnmarshalPEM(pemBytes)
	if err == nil {
		t.Error("expected error on bad key bytes")
	}
}

func TestPrincipal_UnmarshalPEM_Failures(t *testing.T) {
	pr := &Principal{}

	// 1. Bad PEM
	err := pr.UnmarshalPEM([]byte("bad"))
	if err == nil {
		t.Error("expected error on bad pem")
	}

	// 2. Wrong Type
	block := &pem.Block{Type: "WRONG", Bytes: []byte{}}
	pemBytes := pem.EncodeToMemory(block)
	err = pr.UnmarshalPEM(pemBytes)
	if err == nil {
		t.Error("expected error on wrong type")
	}

	// 3. Bad Key Bytes
	block = &pem.Block{Type: "ORACLE PRIVATE KEY", Bytes: []byte("bad key")}
	pemBytes = pem.EncodeToMemory(block)
	err = pr.UnmarshalPEM(pemBytes)
	if err == nil {
		t.Error("expected error on bad key bytes")
	}
}

func TestPrincipal_MustBeValid_Panic(t *testing.T) {

	assert.Panics(t, func() {
		kp := delphi.NewKeyPair(nil) // Zero keypair
		pr := &Principal{
			KeyPair: kp,
			Props:   map[string]string{},
			Peers:   nil,
		}
		pr.MustBeValid()
	})

	assert.Panics(t, func() {
		kp := delphi.NewKeyPair(nil) // Zero keypair
		pr := &Principal{
			KeyPair: kp,
			Props:   nil,
			Peers:   nil,
		}
		pr.MustBeValid()
	})

}
