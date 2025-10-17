package delphi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"crypto"
	"github.com/goombaio/namegenerator"
)

// A Key is either public or private. It combines encryption and signing sub-keys
type Key [2]SubKey

var ZeroKey Key

type PublicKey Key
type PrivateKey Key

func (p PublicKey) Equal(k crypto.PublicKey) bool {
	return Key(p).Equal(k.(Key))
}

func (p PrivateKey) Equal(k crypto.PublicKey) bool {
	return Key(p).Equal(k.(Key))
}

func (k Key) MustBeValid() {
	if k == ZeroKey {
		panic("zero key")
	}
}

func (k Key) Bytes() []byte {
	return append(k[0][:], k[1][:]...)
}

func (k PrivateKey) Bytes() []byte {
	return Key(k).Bytes()
}

func (k PrivateKey) Encryption() SubKey {
	return SubKey(k[0][:])
}

func (k PublicKey) Encryption() SubKey {
	return SubKey(k[0][:])
}

func (k PublicKey) Signing() SubKey {
	return SubKey(k[1][:])
}

func (k PublicKey) Bytes() []byte {
	return Key(k).Bytes()
}

func (k Key) toInt64() int64 {
	var num int64
	buf := bytes.NewReader(k.Bytes())
	err := binary.Read(buf, binary.BigEndian, &num)
	if err != nil {
		// Handle the error appropriately
	}
	return num
}

// A Nickname is a very memorable string for humans only. It has weak uniqueness that is good enough for some uses.
func (k PublicKey) Nickname() string {
	seed := Key(k).toInt64()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()
	//	divine cloud is a zero-key, which is illegal
	//if name == "divine-cloud" {
	//	panic("divine-cloud")
	//}
	return name
}

func (k PrivateKey) Signing() SubKey {
	return SubKey(k[1][:])
}

func (k *Key) Write(p []byte) (int, error) {
	//if len(p) == 0 {
	//	return 0, io.EOF
	//}
	sizeShouldBe := 2 * subKeySize
	if len(p) < sizeShouldBe {
		return 0, fmt.Errorf("size should be %d, but we got %d", sizeShouldBe, len(p))
	}
	copy(k[0][:], p[:subKeySize])
	copy(k[1][:], p[subKeySize:subKeySize*2])
	return subKeySize * 2, nil
}

func (k *PublicKey) Write(p []byte) (int, error) {
	//if len(p) == 0 {
	//	return 0, io.EOF
	//}
	sizeShouldBe := 2 * subKeySize
	if len(p) < sizeShouldBe {
		return 0, fmt.Errorf("size should be %d, but we got %d", sizeShouldBe, len(p))
	}
	copy(k[0][:], p[:subKeySize])
	copy(k[1][:], p[subKeySize:subKeySize*2])
	return subKeySize * 2, nil
}

var ErrWrongSize = errors.New("wrong size")
var ErrZeroKey = errors.New("zero key")

func (k Key) Read(p []byte) (int, error) {
	k.MustBeValid()
	sizeShouldBe := 2 * subKeySize
	if len(p) < sizeShouldBe {
		return 0, fmt.Errorf("%w. Should be %d, but we got %d", ErrWrongSize, sizeShouldBe, len(p))
	}
	i := copy(p[:subKeySize], k[0][:])
	j := copy(p[subKeySize:], k[1][:])
	return i + j, io.EOF
}

func (k Key) Equal(j Key) bool {
	return bytes.Equal(k.Bytes(), j.Bytes())
}

func (k Key) String() string {
	return fmt.Sprintf("%x%x", k[0][:], k[1][:])
}

func (k PublicKey) String() string {
	return fmt.Sprintf("%x%x", k[0][:], k[1][:])
}

func KeyFromString(s string) (Key, error) {
	bin, err := hex.DecodeString(s)
	if err != nil {
		return ZeroKey, fmt.Errorf("could not decode string into key: %w", err)
	}
	return KeyFromBytes(bin)
}

func KeyFromBytes(b []byte) (Key, error) {
	if len(b) != subKeySize*2 {
		return ZeroKey, fmt.Errorf("invalid key size, expected %d, got %d", subKeySize*2, len(b))
	}
	k := &Key{}
	_, err := k.Write(b)
	if err != nil {
		return ZeroKey, fmt.Errorf("could not create key from bytes. %w", err)
	}
	if k.Equal(ZeroKey) {
		return ZeroKey, ErrZeroKey
	}
	return *k, nil
}

func NewKey(randy io.Reader) Key {
	k := Key{}
	if randy != nil {
		randy.Read(k[0][:])
		randy.Read(k[1][:])
	}
	return k
}

func (k PublicKey) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString(k.Bytes())
	return json.Marshal(str)
}

func (k *PublicKey) UnmarshalJSON(data []byte) error {
	var hexString string
	err := json.Unmarshal(data, &hexString)
	if err != nil {
		return err
	}
	bin, err := hex.DecodeString(hexString)
	if err != nil {
		return err
	}

	_, err = k.Write(bin)
	return err
}

func (k Key) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString(k.Bytes())
	return json.Marshal(str)
}

func (k *Key) UnmarshalJSON(data []byte) error {
	var hexString string
	err := json.Unmarshal(data, &hexString)
	if err != nil {
		return err
	}
	bin, err := hex.DecodeString(hexString)
	if err != nil {
		return err
	}

	_, err = k.Write(bin)
	return err
}
