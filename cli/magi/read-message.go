package main

import (
	"os"

	"github.com/sean9999/go-oracle"
)

func ReadMessage(recipient *oracle.Oracle, sender *oracle.Peer, encoding string) (string, error) {
	var r string
	var err error

	var ct oracle.CipherText
	fileName := messageFilePath(sender.Nickname, recipient.Nickname(), encoding)
	bin, err := os.ReadFile(fileName)
	if err != nil {
		return r, err
	}
	if encoding == "pem" {
		err = ct.UnmarshalPEM(bin)
	} else {
		err = ct.UnmarshalIon(bin)
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
