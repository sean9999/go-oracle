package essence

import (
	"crypto"

	util "git.mills.io/prologic/cryptutils/public"
)

type Key interface {
	AsHex() string
	AsBinary() []byte
}

type PublicKey interface {
	Key
	crypto.PublicKey
	Material() *util.PublicKey
}

type PrivateKey interface {
	Key
	crypto.PrivateKey
	Material() *util.PrivateKey
}
