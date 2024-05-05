# Oracle

<img src="go-oracle-gopher.png?v=2" alt="go oracle" title="go oracle" height="250" />

Oracle is a go library that provides the following cryptographic functions:

- generate key-pairs
- encrypt messages
- decrypt messages
- sign messages
- validate messages

Oracle is the basic object that can perform these functions. It also has the concept of a Peer, which is public key. Useful for validating and encrypting.

Keys are Curve25519.

Oracle also provides a binary called `goracle`.