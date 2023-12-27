package main

import (
	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/essence"
)

func ComposeMessage(sender essence.Oracle, recipient essence.Peer, body, encoding string) ([]byte, error) {
	var x []byte
	var err error
	pt := oracle.PlainText{
		Type:    "ORACLE MESSAGE",
		Headers: map[string]string{},
		Bytes:   []byte(body),
	}
	ct, err := sender.EncryptAndSign(&pt, recipient.Public())
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
