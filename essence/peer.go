package essence

// a Peer is an Oracle whose private key is not known, but whose public key is
type Peer interface {
	Public() PublicKey              // required for crypto
	Nickname() string               // derived from the public key
	Annotations() map[string]string // optional key-value pairs
}
