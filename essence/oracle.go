package essence

import (
	"crypto"
	"io"
)

// an Oracle is an entity capable of encrypting, decrypting, signing, and verifying messages
type Oracle interface {
	crypto.Signer
	Encrypter
	Verifier
	Decrypter
	GenerateKeys(io.Reader) error // generates all the necessasry key-pairs for crypto
	Load(io.Reader) error         // loads a config
	Export(io.Writer) error       // exports a config
	Nickname() string             // determanistic and based on the public key
	Peers() map[string]Peer
	Peer(string) (Peer, error)
	AddPeer(Peer) error
	AsPeer() Peer // returns the Oracle as a Peer
}

// a Decrypter can decrypt messages
type Decrypter interface {
	Decrypt(CipherText, Peer) (PlainText, error)
}

// an Encrypter encrypts messages
type Encrypter interface {
	Encrypt(io.Reader, PlainText, Peer) (CipherText, error)
}

// a Verifier can verify signatures
type Verifier interface {
	Verify(pub crypto.PublicKey, msg []byte, sig []byte) bool
}

// a Signer can sign a message, proving that it is the author
// type Signer interface {
// 	Sign(digest []byte) ([]byte, error)
// }
