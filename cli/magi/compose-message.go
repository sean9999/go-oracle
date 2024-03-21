package main

import (
	"crypto/rand"

	"github.com/sean9999/go-oracle"
)

func ComposeMessage(sender *oracle.Oracle, addressee *oracle.Peer, body, encoding string) ([]byte, error) {
	var x []byte
	var err error

	// pt := oracle.PlainText{
	// 	Type:          "ORACLE MESSAGE",
	// 	PlainTextData: []byte(body),
	// }

	dearJohn := oracle.ComposeLetter(addressee.PublicKey, "dear john", []byte(body))

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
