package oracle

import (
	"encoding/binary"
	"errors"
	"io"

	"crypto/ecdh"

	"github.com/goombaio/namegenerator"
	"github.com/sean9999/go-oracle/essence"
)

type oracleMachine struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	peers      map[string]Peer
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
func (o *oracleMachine) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.publicKey.Bytes())
	gen := namegenerator.NewNameGenerator(int64(publicKeyAsInt64))
	return gen.Generate()
}

// Make an Oracle aware of a Peer, so it can encrypt messages or validate signatures
func (o *oracleMachine) AddPeer(p essence.Peer) error {
	o.peers[p.(Peer).Nickname] = p.(Peer)
	return nil
}

// get a Peer from its Nickname
func (o *oracleMachine) Peer(nick string) (essence.Peer, error) {
	p, ok := o.peers[nick]
	if ok {
		return p, nil
	} else {
		return nil, errors.New("no such Peer")
	}
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *oracleMachine) AsPeer() essence.Peer {
	p := Peer{
		PublicKey: o.publicKey,
		Nickname:  o.Nickname(),
	}
	return p
}

// iterate through all known Peers loaded into memory
func (o *oracleMachine) Peers() map[string]essence.Peer {
	m := map[string]essence.Peer{}
	for k, v := range o.peers {
		m[k] = v
	}
	return m
}

// a new Oracle needs some initialization to prevent nil-pointer errors.
func (o *oracleMachine) Initialize() {
	if o.peers == nil {
		o.peers = map[string]Peer{}
	}
}

func (o *oracleMachine) Compose(subject string, body string, recipient essence.Peer) essence.PlainText {
	hdr := map[string]string{
		"subject": subject,
	}
	pt := PlainText{
		Type:          "ORACLE MESSAGE",
		Headers:       hdr,
		PlainTextData: []byte(body),
		recipient:     recipient.Public().(*ecdh.PublicKey),
	}
	return &pt
}

// create a new Oracle with new key-pairs.
func New(rand io.Reader) essence.Oracle {
	orc := oracleMachine{}
	orc.Initialize()
	err := orc.GenerateKeys(rand)
	if err != nil {
		panic(err)
	}
	return &orc
}

// load an Oracle from a file or other io.Reader
func From(r io.Reader) (essence.Oracle, error) {
	//defer r.Close()
	orc := oracleMachine{}
	orc.Initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return &orc, nil
}
