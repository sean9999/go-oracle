package main

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/essence"
)

func ComposeMessage(sender essence.Oracle, addressee essence.Peer, body, encoding string) ([]byte, error) {
	var x []byte
	var err error

	// pt := oracle.PlainText{
	// 	Type:          "ORACLE MESSAGE",
	// 	PlainTextData: []byte(body),
	// }

	peerPub := addressee.Public().(*ecdh.PublicKey)
	dearJohn := oracle.ComposeLetter(peerPub, "dear john", []byte(body))

	//pt := oracle.NewPlainText("ORACLE MESSAGE", map[string]string{}, []byte(body), nil, nil)
	ct, err := sender.Encrypt(rand.Reader, dearJohn, addressee)
	if err != nil {
		return nil, nil
	}
	if encoding == "ion" {
		//x, err = ct.MarshalBinary()
		panic("choose PEM")
	} else {
		x, err = ct.MarshalPEM()
	}
	return x, err
}
