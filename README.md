# Oracle

<img src="go-oracle-gopher.png?v=2" alt="go oracle" title="go oracle" height="250" />

Oracle is a go library that provides the following cryptographic functions:

- generate key-pairs
- encrypt messages
- decrypt messages
- sign messages
- validate messages

Oracle is the basic object that can perform these functions. It also has the concept of a Peer. An Oracle is to a private key as a Peer is to a public key.

Keys are Curve25519. Messages are encrypted using ChaCha20-Poly1305 AEAD. Perfect forward secrecy is assured by making use of one-time ephemeral keys. 

This project is heavily inspired by [age](https://github.com/C2SP/C2SP/blob/main/age.md), especially with respect to cryptographic design.  However, I beleive that Oracle provides the following advantages, making it a better choice in some situations:

- Simpler API, doing away with unesseary abstractions
- A simple, standard format for messages (PEM)
- Package first. Oracle is first and foremost a Go package with a sensible API
- Do one thing and do it well. The companion binary `goracle` honours the Linux philosophy by accepting input from stdin and producing output to stdout, unlocking composability.

Oracle also comes with a binary called `pemreader` that reads PEM files.