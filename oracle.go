package oracle

import (
	"encoding/hex"
	"errors"
	"io"

	util "git.mills.io/prologic/cryptutils/public"
	"github.com/sean9999/go-oracle/essence"
)

type Oracle struct {
	privateKey *PrivateKey
	peers      map[string]Peer
}

func (o *Oracle) Public() PublicKey {
	return PublicKey{o.privateKey.Material().PublicKey}
}

func (o *Oracle) PublicKeyAsHex() string {
	b, _ := util.MarshalPublic(o.privateKey.material.PublicKey)
	txt := hex.EncodeToString(b)
	return txt
}

func (o *Oracle) PrivateKeyAsHex() string {
	b, _ := util.MarshalPrivate(o.privateKey.material)
	txt := hex.EncodeToString(b)
	return txt
}

func (o *Oracle) Decrypt(ct essence.CipherText) (essence.PlainText, error) {
	var err error
	bin, err := ct.MarshalBinary()
	plain, ok := util.Decrypt(o.privateKey.material, bin)
	if !ok {
		err = errors.New("decryption failed")
	}
	theType, theHeaders, _ := ct.Values()
	pt := PlainText{theType, theHeaders, plain}
	return &pt, err
}

func (o *Oracle) DecryptAndVerify(pub essence.PublicKey, ct essence.CipherText) (essence.PlainText, error) {
	var err error
	//bin, err := ct.MarshalBinary()
	t, h, b := ct.Values()
	plain, ok := util.DecryptAndVerify(o.privateKey.material, pub.Material(), b)
	if !ok {
		err = errors.New("decryption and/or verification failed")
	}
	pt := PlainText{
		Type:    t,
		Headers: h,
		Bytes:   plain,
	}
	return &pt, err
}

func (o *Oracle) Encrypt(pt essence.PlainText, recipient essence.PublicKey) (essence.CipherText, error) {
	var err error

	t, h, plainBytes := pt.Values()

	bin, ok := util.Encrypt(recipient.Material(), plainBytes)
	if !ok {
		err = errors.New("encryption failed")
	}
	h["From"] = o.Nickname()
	h["To"] = NicknameFromPublicKey(recipient.(PublicKey))
	ct := CipherText{
		Type:    t,
		Headers: h,
		Bytes:   bin,
	}
	return &ct, err
}

func (o *Oracle) EncryptAndSign(pt essence.PlainText, recipient essence.PublicKey) (essence.CipherText, error) {
	var err error

	t, h, plainBytes := pt.Values()

	bin, ok := util.EncryptAndSign(o.privateKey.material, recipient.Material(), plainBytes)
	if !ok {
		err = errors.New("encryption and/or signature failed")
	}
	h["From"] = o.Nickname()
	h["To"] = NicknameFromPublicKey(recipient.(PublicKey))
	ct := CipherText{
		Type:    t,
		Headers: h,
		Bytes:   bin,
	}
	return &ct, err
}

// @note: we should be clear about what we're signing
func (o *Oracle) Sign(msg []byte) ([]byte, error) {
	sig, ok := util.Sign(o.privateKey.material, msg)
	if !ok {
		return nil, errors.New("signing failed")
	}
	return sig, nil
}

func (o *Oracle) Verify(pub essence.PublicKey, msg []byte, sig []byte) bool {
	return util.Verify(pub.Material(), msg, sig)
}

// note: The public key is intrinsic to the private key
func (o *Oracle) GenerateKeys() error {
	priv, err := util.GenerateKey()
	if err != nil {
		return err
	}
	o.privateKey = &PrivateKey{priv}
	return nil
}

//	to make it easier to tell Peers apart, a deterministic nickname
//
// can be derived from any PublicKey.
func (o *Oracle) Nickname() string {
	return NicknameFromPublicKey(o.Public())
}

// Make an Oracle aware of a Peer, so it can encrypt messages or validate signatures
func (o *Oracle) AddPeer(p essence.Peer) error {
	o.peers[p.Nickname()] = p.(Peer)
	return nil
}

// get a Peer from it's Nickname
func (o *Oracle) Peer(nick string) (essence.Peer, error) {
	p, ok := o.peers[nick]
	if ok {
		return p, nil
	} else {
		return nil, errors.New("could not find peer")
	}
}

// Export the Oracle as a Peer, ensuring only public information is exported
func (o *Oracle) AsPeer() essence.Peer {
	p := Peer{}
	p["Nickname"] = o.Nickname()
	p["PublicKey"] = o.PublicKeyAsHex()
	return p
}

// iterate through all known Peers loaded into memory
func (o *Oracle) Peers() []essence.Peer {
	peers := []essence.Peer{}
	for _, p := range o.peers {
		peers = append(peers, p)
	}
	return peers
}

// a new Oracle needs some initialization to prevent nil-pointer errors.
func (o *Oracle) Initialize() {
	if o.peers == nil {
		o.peers = map[string]Peer{}
	}
}

// create a new Oracle, with new key-pairs.
func New() essence.Oracle {
	orc := Oracle{}
	orc.Initialize()
	err := orc.GenerateKeys()
	if err != nil {
		panic(err)
	}
	return &orc
}

// load an Oracle from a file or other source of io
func From(r io.Reader) (essence.Oracle, error) {
	//defer r.Close()
	orc := Oracle{}
	orc.Initialize()
	err := orc.Load(r)
	if err != nil {
		return nil, err
	}
	return &orc, nil
}
