package oracle

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"crypto/ecdh"

	"github.com/goombaio/namegenerator"
)

type Oracle struct {
	privateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
	Peers      map[string]Peer
}

// func (o *oracleMachine) EncryptAndSign(pt essence.PlainText, recipient essence.PublicKey) (essence.CipherText, error) {
// 	var err error

// 	t, h, plainBytes := pt.Values()

// 	bin, ok := util.EncryptAndSign(o.privateKey.material, recipient.Material(), plainBytes)
// 	if !ok {
// 		err = errors.New("encryption and/or signature failed")
// 	}
// 	h["From"] = o.Nickname()
// 	h["To"] = NicknameFromPublicKey(recipient.(publicKey))
// 	ct := CipherText{
// 		Type:    t,
// 		Headers: h,
// 		Bytes:   bin,
// 	}
// 	return &ct, err
// }

// // @note: we should be clear about what we're signing
// func (o *oracleMachine) Sign(msg []byte) ([]byte, error) {
// 	sig, ok := util.Sign(o.privateKey.material, msg)
// 	if !ok {
// 		return nil, errors.New("signing failed")
// 	}
// 	return sig, nil
// }

// func (o *oracleMachine) Verify(pub essence.PublicKey, msg []byte, sig []byte) bool {
// 	return util.Verify(pub.Material(), msg, sig)
// }

//	to make it easier to tell Peers apart, a deterministic nickname
//
// can be derived from any PublicKey.
func (o *Oracle) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.PublicKey.Bytes())
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// Make an Oracle aware of a Peer, so it can encrypt messages or validate signatures
func (o *Oracle) AddPeer(p Peer) error {
	o.Peers[p.Nickname] = p
	return nil
}

// get a Peer from its Nickname
func (o *Oracle) Peer(nick string) (*Peer, error) {
	p, ok := o.Peers[nick]
	if ok {
		return &p, nil
	} else {
		return nil, errors.New("no such Peer")
	}
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *Oracle) AsPeer() *Peer {
	p := Peer{
		PublicKey: o.PublicKey,
		Nickname:  o.Nickname(),
	}
	return &p
}

// create a new Oracle with new key-pairs.
func New(rand io.Reader) *Oracle {
	orc := Oracle{}
	orc.initialize()
	err := orc.GenerateKeys(rand)
	if err != nil {
		panic(err)
	}
	return &orc
}

// load an Oracle from a file or other io.Reader
func From(r io.Reader) (*Oracle, error) {
	//defer r.Close()
	orc := Oracle{}
	orc.initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return &orc, nil
}

func FromFile(path string) (*Oracle, error) {
	configFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return From(configFile)
}

// a new Oracle needs some initialization to prevent nil-pointer errors.
func (o *Oracle) initialize() {
	if o.Peers == nil {
		o.Peers = map[string]Peer{}
	}
}
