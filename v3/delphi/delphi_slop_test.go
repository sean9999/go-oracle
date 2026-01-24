package delphi

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

type faultyReader struct{}

func (f faultyReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("forced error")
}

type partialFaultyReader struct {
	readCnt int
	limit   int
}

func (r *partialFaultyReader) Read(p []byte) (n int, err error) {
	if r.readCnt >= r.limit {
		return 0, errors.New("forced error")
	}
	remaining := r.limit - r.readCnt
	toRead := len(p)
	if toRead > remaining {
		toRead = remaining
	}
	// fill with zeros
	for i := 0; i < toRead; i++ {
		p[i] = 0
	}
	r.readCnt += toRead
	if toRead < len(p) {
		return toRead, errors.New("forced error")
	}
	return toRead, nil
}

func TestPublicKey_Equal(t *testing.T) {
	kp := NewKeyPair(rand.Reader)
	pub := kp.PublicKey()
	// Pass Key type to satisfy the implementation's type assertion
	if !pub.Equal(Key(pub)) {
		t.Error("PublicKey should equal itself")
	}
}

func TestPrivateKey_Equal(t *testing.T) {
	kp := NewKeyPair(rand.Reader)
	priv := kp.PrivateKey()
	// Pass Key type to satisfy the implementation's type assertion
	if !priv.Equal(Key(priv)) {
		t.Error("PrivateKey should equal itself")
	}
}

func TestPublicKey_UnmarshalJSON_Error(t *testing.T) {
	var pub PublicKey
	// "zz" is valid JSON string but invalid hex
	err := json.Unmarshal([]byte(`"zz"`), &pub)
	if err == nil {
		t.Error("expected error unmarshalling invalid hex")
	}
}

func TestKeyPair_UnmarshalJSON_Error(t *testing.T) {
	var kp KeyPair
	// "zz" is valid JSON string but invalid hex
	err := json.Unmarshal([]byte(`"zz"`), &kp)
	if err == nil {
		t.Error("expected error unmarshalling invalid hex")
	}
}

func TestNewKeyPair_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewKeyPair(faultyReader{})
}

func TestNewKeyPair_Panic_Second(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	// Allow first key generation (32 bytes) to succeed, fail the second
	NewKeyPair(&partialFaultyReader{limit: 32})
}

func TestKeyPair_Public(t *testing.T) {
	kp := NewKeyPair(rand.Reader)
	if kp.Public() == nil {
		t.Error("Public() returned nil")
	}
}

func TestKeyPair_Decrypt_Success(t *testing.T) {
	alice := NewKeyPair(rand.Reader)
	bob := NewKeyPair(rand.Reader)

	msg := []byte("hello world")
	aad := []byte("header data")

	sec, eph, err := bob.GenerateSharedSecret(rand.Reader, alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 12)
	rand.Read(nonce)

	cipherText, err := bob.Seal(sec, msg, nonce, aad)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := alice.Decrypt(cipherText, eph, nonce, aad)
	if err != nil {
		t.Fatal(err)
	}

	if string(plain) != string(msg) {
		t.Errorf("decryption failed: got %s, want %s", plain, msg)
	}
}

func TestKeyPair_Decrypt_Failures(t *testing.T) {
	kp := NewKeyPair(rand.Reader)

	// 1. extractSharedSecret failure (bad eph key size)
	_, err := kp.Decrypt(nil, []byte("bad"), nil, nil)
	if err == nil {
		t.Error("expected error on bad eph key")
	}
}

func TestKeyPair_Seal_Failure(t *testing.T) {
	kp := NewKeyPair(rand.Reader)
	// Pass invalid secret size (not 32 bytes)
	_, err := kp.Seal([]byte("bad key"), nil, nil, nil)
	if err == nil {
		t.Error("expected error on bad secret size")
	}
}

func TestKeyPair_GenerateSharedSecret_Failures(t *testing.T) {
	kp := NewKeyPair(rand.Reader)

	// Randomness read failure
	_, _, err := kp.GenerateSharedSecret(faultyReader{}, kp.PublicKey())
	if err == nil {
		t.Error("expected error on faulty reader")
	}
}