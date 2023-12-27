package oracle_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/sean9999/go-oracle"
)

const ZERO_PRIVATE_KEY_AS_HEX = "030000002000000000000000000000000000000000000000000000000000000000000000000300000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000020000000000000000000000000000000000000000000000000000000000000000003000000200000000000000000000000000000000000000000000000000000000000000000"

func TestNewPrivateKey(t *testing.T) {

	pk := oracle.NewPrivateKey()

	t.Run("new private key is valid", func(t *testing.T) {
		want := true
		got := pk.Valid()
		if got != want {
			t.Errorf("wanted %t but got %t", want, got)
		}
	})

	t.Run("new private key is not a bunch of zeros", func(t *testing.T) {
		dontWant := ZERO_PRIVATE_KEY_AS_HEX
		got := pk.AsHex()
		if got == dontWant {
			t.Errorf("A new private key should not be a bunch of zeros")
		}
	})

	t.Run("new private key is not nil", func(t *testing.T) {
		got := pk.AsBinary()
		if got == nil {
			t.Errorf("A new private key should not be nil")
		}
	})

}

func TestPrivateKey(t *testing.T) {

	t.Run("nil key is not valid", func(t *testing.T) {
		want := false
		got := oracle.NilPrivateKey.Valid()
		if got != want {
			t.Errorf("wanted %v but got %#v", want, got)
		}
	})

	t.Run("hex value of nil key is zero-length string", func(t *testing.T) {
		want := ""
		got := oracle.NilPrivateKey.AsHex()
		if got != want {
			t.Errorf("wanted %q but got %q", want, got)
		}
	})

	t.Run("binary value of nil key is a nil byte slice", func(t *testing.T) {
		var want []byte
		got := oracle.NilPrivateKey.AsBinary()
		if !reflect.DeepEqual(want, got) {
			t.Errorf("wanted %#v but got %#v", want, got)
		}
	})

	t.Run("The PublicKey of a nil private key is a nil publickey", func(t *testing.T) {
		got := oracle.NilPrivateKey.Public().AsHex()
		want := ""
		if got != want {
			t.Errorf("wanted %q but got %q", want, got)
		}
	})

	t.Run("Zero key is a bunch of zeros", func(t *testing.T) {
		got := oracle.ZeroPrivateKey.AsHex()
		want := ZERO_PRIVATE_KEY_AS_HEX
		if got != want {
			t.Errorf("wanted a bunch of zeros but got %q", got)
		}
	})

	t.Run("Zero key is valid", func(t *testing.T) {
		got := oracle.ZeroPrivateKey.Valid()
		want := true
		if got != want {
			t.Errorf("wanted %t but got %t", want, got)
		}
	})

	t.Run("The public key of a zero private key is a bunch of zeros", func(t *testing.T) {
		got := oracle.ZeroPrivateKey.Public().AsHex()
		want := "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		if got != want {
			t.Errorf("wanted %q but got %q", want, got)
		}
	})

	t.Run(fmt.Sprintf("Zero key's nickname is %q", oracle.ZERO_NICKNAME), func(t *testing.T) {
		got := oracle.NicknameFromPublicKey(oracle.ZeroPrivateKey.Public())
		want := oracle.ZERO_NICKNAME
		if got != want {
			t.Errorf("wanted %q but got %q", want, got)
		}
	})

}
