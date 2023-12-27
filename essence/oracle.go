package essence

import (
	"io"
)

// an Oracle is an entity capable of encrypting, decrypting, signing, and verifying messages
type Oracle interface {
	Signer
	Decrypter
	Encrypter
	Verifier
	GenerateKeys() error    // generates all the necessasry key-pairs for crypto
	Load(io.Reader) error   // loads a config
	Export(io.Writer) error // exports a config
	Nickname() string       // determanistic and based on the public key
	Peers() []Peer
	Peer(string) (Peer, error)
	AddPeer(Peer) error
	AsPeer() Peer // returns the Oracle as a Peer
}

// a Decrypter can decrypt messages
type Decrypter interface {
	Decrypt(CipherText) (PlainText, error)
	DecryptAndVerify(PublicKey, CipherText) (PlainText, error)
}

// an Encrypter encrypts messages
type Encrypter interface {
	Encrypt(PlainText, PublicKey) (CipherText, error)
	EncryptAndSign(PlainText, PublicKey) (CipherText, error)
}

// a Verifier can verify signatures
type Verifier interface {
	Verify(pub PublicKey, msg []byte, sig []byte) bool
}

// a Signer can sign a message, proving that it is the author
type Signer interface {
	Sign(digest []byte) ([]byte, error)
}
