package main

import (
	"crypto/rand"

	"github.com/sean9999/go-oracle"
)

func ComposeMessage(sender *oracle.Oracle, addressee *oracle.Peer, body, encoding string) ([]byte, error) {
	var x []byte
	var err error
	dearJohn := sender.Compose("dear john", []byte(body), addressee)
	ct, err := sender.Encrypt(rand.Reader, dearJohn, addressee)
	if err != nil {
		return nil, nil
	}
	if encoding == "ion" {
		x, err = ct.MarshalIon()
	} else {
		x, err = ct.MarshalPEM()
	}
	return x, err
}
