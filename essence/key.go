package essence

import (
	"crypto"

	util "git.mills.io/prologic/cryptutils/public"
)

// a Key is that behaviour that is common between PublicKeys and PrivateKeys
type Key interface {
	AsHex() string
	AsBinary() []byte
}

// a PublicKey is a Key that can be used in cryptographic operations
type PublicKey interface {
	Key
	crypto.PublicKey
	Material() *util.PublicKey
}

// a PrivateKey is a Key, meant to be private, from which a PublicKey can be derived.
type PrivateKey interface {
	Key
	crypto.PrivateKey
	Material() *util.PrivateKey
}
