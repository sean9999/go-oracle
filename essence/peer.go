package essence

// a Peer is an Oracle whose private key is not known, but whose public key is
//
//	It can also hold arbitrary key-value pairs
type Peer interface {
	Public() PublicKey
	Nickname() string
	Annotations() map[string]string
}
