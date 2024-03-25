package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sean9999/go-oracle"
)

func main() {

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	configLocation := filepath.Join(home, ".config/goracle/conf.toml")

	configPtr := flag.String("config", configLocation, "location of config file")

	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encryptCmdInputFile := encryptCmd.String("input", "", "input file")
	encryptCmdOutputFile := encryptCmd.String("output", "", "output file")
	encryptCmdRecipient := encryptCmd.String("recipient", "", "pubkey or nickname of recipient")
	// decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	// signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	// verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)

	flag.Parse()

	var goracle *oracle.Oracle

	fd, err := os.Open(*configPtr)
	if err != nil {
		fd, err := os.Create(*configPtr)
		if err != nil {
			panic(err)
		}
		goracle = oracle.New(rand.Reader)
		goracle.Export(fd)
	} else {
		goracle, err = oracle.From(fd)
		if err != nil {
			goracle = oracle.New(rand.Reader)
			goracle.Export(fd)
		}
	}

	switch os.Args[1] {
	case "encrypt":

		encryptCmd.Parse(os.Args[2:])
		fmt.Println("encryptCmdfileName: ", *encryptCmdInputFile)
		fileContents, err := os.ReadFile(*encryptCmdInputFile)
		if err != nil {
			panic(err)
		}
		recipient, err := goracle.Peer(*encryptCmdRecipient)
		if err != nil {
			panic(err)
		}
		plainTextMessage := goracle.Compose("msg", fileContents, recipient)
		cryptMsg, err := goracle.Encrypt(rand.Reader, plainTextMessage, recipient)
		if err != nil {
			panic(err)
		}

		pem, err := cryptMsg.MarshalPEM()
		if err != nil {
			panic(err)
		}
		os.WriteFile(*encryptCmdOutputFile, pem, 0640)

		//fmt.Println("FILE IS ", string(fileContents))

	case "decrypt":

	case "sign":

	case "verify":

	case "info":
		goracle.Export(os.Stdout)
	}

}
