package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sean9999/go-oracle"
	"github.com/sean9999/go-oracle/essence"
)

const CONF_ROOT = "./testdata"

func configFilePath(nick string) string {
	return fmt.Sprintf("%s/%s.config.toml", CONF_ROOT, nick)
}

func messageFilePath(from, to, format string) string {
	return fmt.Sprintf("%s/%s-to-%s.msg.%s", CONF_ROOT, from, to, format)
}

func StringPrompt(label string) string {
	var s string
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, label+" ")
		s, _ = r.ReadString('\n')
		if s != "" {
			break
		}
	}
	return strings.TrimSpace(s)
}

var orc essence.Oracle

func processCommand(cmd string) {
	switch cmd {

	case "compose-msg":
		body := StringPrompt("Type the message: ")
		recipient := StringPrompt("Send to who? ")
		encoding := StringPrompt("encoded as what? ")
		peer, err := orc.Peer(recipient)
		if err != nil {
			fmt.Println(err)
		}
		bits, err := ComposeMessage(orc, peer, body, encoding)
		if err != nil {
			fmt.Println(err)
			return
		} else {

			fileName := messageFilePath(orc.Nickname(), peer.Nickname(), encoding)
			fd, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				fmt.Println(err)
				return
			}
			i, err := fd.Write(bits)
			if err != nil {
				fmt.Println(err)
				return
			} else {
				fmt.Printf("%d bytes written to %s", i, fileName)
			}
			fd.Close()

		}

	case "read-msg":
		sender := StringPrompt("Who sent it? ")
		encoding := StringPrompt("encoded as what? ")
		peer, err := orc.Peer(sender)
		if err != nil {
			fmt.Println(err)
			return
		}
		msg, err := ReadMessage(orc, peer.(oracle.Peer), encoding)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			fmt.Println(msg)
		}

	case "help":
		fmt.Println("help")
	case "new":
		orc = oracle.New()
	case "show":
		if orc == nil {
			fmt.Println("you have to initialize first")
		} else {
			orc.Export(os.Stdout)
		}
	case "load":
		nickname := StringPrompt("Load what? ")
		path := configFilePath(nickname)
		//path := fmt.Sprintf("%s/%s.v2.oracle.config.toml", CONF_ROOT, nickname)
		fd, err := os.OpenFile(path, os.O_RDONLY, 0600)
		if err != nil {
			fmt.Println(err)
		}
		orc, err = oracle.From(fd)
		if err != nil {
			fmt.Println(err)
		}
	case "peers":
		fmt.Println(orc.Peers())
	case "add-peer":
		pubKey := StringPrompt("Enter Pubkey: ")
		p := oracle.PeerFromHex(pubKey)
		orc.AddPeer(p)
		orc.Export(os.Stdout)
	case "save":
		//path := fmt.Sprintf("%s/%s.v2.oracle.config.toml", CONF_ROOT, orc.Nickname())
		path := configFilePath(orc.Nickname())
		fd, err := os.Create(path)
		if err != nil {
			fmt.Println(err)
		}
		err = orc.Export(fd)
		if err != nil {
			fmt.Println(err)
		}
	case "":
		// no-op
	default:
		fmt.Println("command not found")
	}
}

func main() {
	fmt.Println("Enter a command")

	var cmd string
	for cmd != "exit" {
		cmd = StringPrompt("★ ")
		processCommand(cmd)
	}

	fmt.Println("goodbye")
}
