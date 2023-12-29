package main

import (
	"os"

	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/essence"
)

func ReadMessage(recipient essence.Oracle, sender oracle.Peer, encoding string) (string, error) {
	var r string
	var err error

	var ct oracle.CipherText
	fileName := messageFilePath(sender.Nick(), recipient.Nickname(), encoding)
	bin, err := os.ReadFile(fileName)
	if err != nil {
		return r, err
	}
	if encoding == "pem" {
		err = ct.UnmarshalPEM(bin)
	} else {
		err = ct.UnmarshalBinary(bin)
	}
	if err != nil {
		return r, err
	}
	pt, err := recipient.Decrypt(&ct, sender)
	if err != nil {
		return r, err
	}
	return pt.String(), nil
}
