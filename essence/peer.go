package essence

import (
	"crypto"
)

// a Peer is an Oracle whose private key is not known, but whose public key is
type Peer interface {
	Public() crypto.PublicKey
	Nick() string
}
