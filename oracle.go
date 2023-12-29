package oracle

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/goombaio/namegenerator"
	"github.com/sean9999/go-oracle/essence"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type oracleMachine struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	peers      map[string]Peer
}

func (o *oracleMachine) Public() crypto.PublicKey {
	return o.privateKey.Public()
}

func (o *oracleMachine) PublicKeyAsHex() []byte {
	x := make([]byte, len(o.publicKey))
	hex.Encode(x, o.publicKey)
	return x
}

func (o *oracleMachine) PrivateKeyAsHex() []byte {
	x := make([]byte, len(o.privateKey))
	hex.Encode(x, o.privateKey)
	return x
}

func (o *oracleMachine) SharedSecret(counterParty essence.Peer) ([]byte, error) {
	secret, err := curve25519.X25519(o.privateKey.Seed(), counterParty.Public().(ed25519.PublicKey))
	return secret, err
}

func (o *oracleMachine) Decrypt(ct essence.CipherText, sender essence.Peer) (essence.PlainText, error) {
	var err error
	secret, err := o.SharedSecret(sender)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	encryptedMsg := ct.Bytes()
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
	plainBytes, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	pt := NewPlainText(ct.Type(), ct.Headers(), plainBytes, ct.Signature(), ct.Nonce())
	return &pt, nil
}

func (o *oracleMachine) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(o.privateKey, msg)
	return sig, nil
}

func (o *oracleMachine) Verify(pubkey crypto.PublicKey, msg []byte, sig []byte) bool {
	return ed25519.Verify(pubkey.(ed25519.PublicKey), msg, sig)
}

func (o *oracleMachine) Encrypt(rand io.Reader, pt essence.PlainText, recipient essence.Peer) (essence.CipherText, error) {
	// @todo: instead of passing nil for AES additional data, pass in headers, type, or both
	plainData := pt.Bytes()

	secret, err := o.SharedSecret(recipient)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plainData)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	cipherBytes := aead.Seal(nonce, nonce, plainData, nil)
	ct := NewCipherText(pt.Type(), pt.Headers(), cipherBytes, nil, nil)
	return &ct, nil
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

func (o *oracleMachine) GenerateKeys(rand io.Reader) error {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return err
	}
	o.privateKey = priv
	o.publicKey = pub
	return nil
}

//	to make it easier to tell Peers apart, a deterministic nickname
//
// can be derived from any PublicKey.
func (o *oracleMachine) Nickname() string {
	publicKeyAsInt64 := binary.BigEndian.Uint64(o.publicKey)
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
