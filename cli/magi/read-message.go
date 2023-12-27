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
	//fileName := fmt.Sprintf("%s/msg-from-%s-to-%s.ion", CONF_ROOT, sender.Nickname(), recipient.Nickname())

	fileName := messageFilePath(sender.Nickname(), recipient.Nickname(), encoding)

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
	pt, err := recipient.DecryptAndVerify(sender.Public(), &ct)
	if err != nil {
		return r, err
	}

	return pt.String(), nil
}
