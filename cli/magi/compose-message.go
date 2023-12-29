package main

import (
	"crypto/rand"

	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/essence"
)

func ComposeMessage(sender essence.Oracle, recipient essence.Peer, body, encoding string) ([]byte, error) {
	var x []byte
	var err error

	pt := oracle.NewPlainText("ORACLE MESSAGE", map[string]string{}, []byte(body), nil, nil)
	ct, err := sender.Encrypt(rand.Reader, &pt, recipient)
	if err != nil {
		return nil, nil
	}
	if encoding == "ion" {
		x, err = ct.MarshalBinary()
	} else {
		x, err = ct.MarshalPEM()
	}
	return x, err
}
