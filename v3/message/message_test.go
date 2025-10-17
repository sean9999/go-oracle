package message

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sean9999/go-oracle/v3/delphi"
	"io"
	"os"
	"testing"
	"time"

	smap "github.com/sean9999/go-stable-map"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

type mockRand byte

func (f mockRand) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

type mockSigner struct {
	shouldFail bool
}

func (m *mockSigner) Public() crypto.PublicKey {
	return []byte("mock_public_key")
}

func (m *mockSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if m.shouldFail {
		return nil, errors.New("signer failed")
	}
	// Simple "signature" for testing
	sig := append([]byte("signed_"), digest...)
	return sig, nil
}

type mockVerifier struct {
	shouldFail bool
}

func (m *mockVerifier) Verify(_ crypto.PublicKey, digest []byte, signature []byte) bool {
	if m.shouldFail {
		return false
	}
	expectedSig := append([]byte("signed_"), digest...)
	return bytes.Equal(expectedSig, signature)
}

type mockDecrypter struct {
	shouldFail bool
}

func (m *mockDecrypter) Public() crypto.PublicKey { return nil }

func (m *mockDecrypter) Decrypt(msg, _, _, _ []byte) (plaintext []byte, err error) {
	if m.shouldFail {
		return nil, errors.New("decryption failed")
	}
	// Simple "decryption" for testing
	return bytes.TrimPrefix(msg, []byte("encrypted_")), nil
}

type mockEncrypter struct {
	secretFail bool
	encFail    bool
}

func (m *mockEncrypter) GenerateSharedSecret(_ io.Reader, _ delphi.PublicKey) ([]byte, []byte, error) {
	if m.secretFail {
		return nil, nil, errors.New("shared secret failed")
	}
	return []byte("mock_secret"), []byte("mock_ephemeral_key"), nil
}

func (m *mockEncrypter) Seal(_ []byte, plainText []byte, _ []byte, _ []byte) ([]byte, error) {
	if m.encFail {
		return nil, errors.New("symmetric encryption failed")
	}
	return append([]byte("encrypted_"), plainText...), nil
}

// --- Tests ---

func TestNewMessage(t *testing.T) {

	t.Run("with reader", func(t *testing.T) {
		msg := NewMessage(mockRand(1))
		require.NotNil(t, msg)
		assert.NotNil(t, msg.Nonce)
		assert.Len(t, msg.Nonce, chacha20poly1305.NonceSize)
		expectedNonce := make([]byte, chacha20poly1305.NonceSize)
		for i := range expectedNonce {
			expectedNonce[i] = 1
		}
		assert.Equal(t, expectedNonce, msg.Nonce)
	})

	t.Run("with nil reader", func(t *testing.T) {
		msg := NewMessage(nil)
		require.NotNil(t, msg)
		assert.Nil(t, msg.Nonce)
	})
	t.Run("nil nonce", func(t *testing.T) {
		msg := NewMessage(nil)
		assert.NotNil(t, msg)
		assert.Nil(t, msg.Nonce)
	})
	t.Run("non nil nonce", func(t *testing.T) {
		randy := dRand(t, 3)
		msg := NewMessage(randy)
		assert.NotNil(t, msg)
		assert.NotNil(t, msg.Nonce)
	})
}

func TestMessage_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		msg     *Message
		wantErr bool
		errText string
	}{
		{"valid plain", &Message{PlainText: []byte("hi"), Nonce: []byte("nonce")}, false, ""},
		{"valid encrypted", &Message{CipherText: []byte("ciph"), Nonce: []byte("nonce")}, false, ""},
		{"invalid both plain and encrypted", &Message{PlainText: []byte("hi"), CipherText: []byte("ciph"), Nonce: []byte("nonce")}, true, "both encrypted and plain"},
		{"invalid neither plain nor encrypted", &Message{Nonce: []byte("nonce")}, true, "neither encrypted nor plain"},
		{"invalid encrypted with no nonce", &Message{CipherText: []byte("ciph")}, true, "encrypted data, but no nonce"},
		{"invalid signature with no nonce", &Message{PlainText: []byte("hi"), Signature: []byte("sig")}, true, "signature, but no nonce"},
		{"valid signature with nonce", &Message{PlainText: []byte("hi"), Nonce: []byte("nonce"), Signature: []byte("sig")}, false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.msg.Validate()
			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errText)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMessage_MustValidate(t *testing.T) {
	t.Run("panics on invalid message", func(t *testing.T) {
		invalidMsg := &Message{}
		assert.Panics(t, func() {
			invalidMsg.MustValidate()
		})
	})
	t.Run("panics on invalid message using constructor", func(t *testing.T) {
		msg := NewMessage(nil)
		assert.Panics(t, func() {
			msg.MustValidate()
		})
	})
	t.Run("does not panic on valid message", func(t *testing.T) {
		validMsg := &Message{PlainText: []byte("hi"), Nonce: []byte("nonce")}
		assert.NotPanics(t, func() {
			validMsg.MustValidate()
		})
	})
}

func TestMessage_Digest(t *testing.T) {

	randy := dRand(t, 7)
	msg := NewMessage(randy)

	t.Run("returns error on invalid message", func(t *testing.T) {
		msg := &Message{}
		_, err := msg.Digest()
		assert.Error(t, err)
	})

	t.Run("calculates digest for plain message", func(t *testing.T) {
		msg1 := &Message{PlainText: []byte("hi"), Nonce: []byte("nonce"), AAD: []byte("aad")}
		digest1, err := msg1.Digest()
		require.NoError(t, err)

		msg2 := &Message{PlainText: []byte("different"), Nonce: []byte("nonce"), AAD: []byte("aad")}
		digest2, err := msg2.Digest()
		require.NoError(t, err)

		assert.NotEmpty(t, digest1)
		assert.NotEqual(t, digest1, digest2)
	})

	t.Run("calculates digest for encrypted message", func(t *testing.T) {
		msg := &Message{CipherText: []byte("ciph"), Nonce: []byte("nonce"), AAD: []byte("aad")}
		digest, err := msg.Digest()
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
	})

	t.Run("happy path", func(t *testing.T) {
		msg.PlainText = []byte("hello world")
		dig, err := msg.Digest()
		assert.NoError(t, err)
		assert.Equal(t, "07070707070707070707070768656c6c6f20776f726c64e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(dig))
	})

	t.Run("encrypted message", func(t *testing.T) {
		alice := alice(t)
		bob := bob(t)
		err := msg.Encrypt(randy, bob.PublicKey(), alice)
		assert.NoError(t, err)
		dig, err := msg.Digest()
		assert.NoError(t, err)
		assert.Equal(t, "0707070707070707070707074d8c17f1ec5b98a761706549bdff277d00944c28bf4f5bca132922e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(dig))
	})

	t.Run("encrypt a message with no initial nonce", func(t *testing.T) {
		alice := alice(t)
		bob := bob(t)
		msg := new(Message)
		msg.PlainText = []byte("hello world")
		err := msg.Encrypt(randy, bob.PublicKey(), alice)
		assert.NoError(t, err)
		dig, err := msg.Digest()
		assert.NoError(t, err)
		assert.Equal(t, "0707070707070707070707074d8c17f1ec5b98a761706549bdff277d00944c28bf4f5bca132922e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(dig))
	})

	t.Run("you can't encrypt a message with no plain text", func(t *testing.T) {
		alice := alice(t)
		bob := bob(t)
		msg := new(Message)
		err := msg.Encrypt(randy, bob.PublicKey(), alice)
		assert.Error(t, err)
	})

}

func TestMessage_SerializeDeserialize(t *testing.T) {
	originalMsg := &Message{
		PlainText:    []byte("hello"),
		AAD:          []byte("meta"),
		Nonce:        []byte("123456789012"),
		EphemeralKey: []byte("ephkey"),
		Signature:    []byte("siggy"),
	}

	serialized := originalMsg.Serialize()
	assert.NotEmpty(t, serialized)

	deserializedMsg := &Message{}
	deserializedMsg.Deserialize(serialized)

	assert.Equal(t, originalMsg, deserializedMsg)

	t.Run("deserialize panics on bad data", func(t *testing.T) {
		assert.Panics(t, func() {
			badMsg := &Message{}
			badMsg.Deserialize([]byte("this is not msgpack"))
		})
	})
}

func TestMessage_EncryptDecrypt(t *testing.T) {
	msg := &Message{PlainText: []byte("secret data"), Nonce: []byte("nonce")}
	encrypter := &mockEncrypter{}
	decrypter := &mockDecrypter{}
	randy := mockRand(1)

	recipientPubKey := new(delphi.PublicKey)

	bug := make([]byte, 64)
	_, err := recipientPubKey.Write(bug)
	assert.NoError(t, err)

	t.Run("successful encrypt", func(t *testing.T) {
		err := msg.Encrypt(randy, delphi.PublicKey{}, encrypter)
		require.NoError(t, err)

		assert.Nil(t, msg.PlainText)
		assert.NotNil(t, msg.CipherText)
		assert.Equal(t, []byte("encrypted_secret data"), msg.CipherText)
		assert.Equal(t, []byte("mock_ephemeral_key"), msg.EphemeralKey)

		t.Run("successful decrypt", func(t *testing.T) {
			err = msg.Decrypt(decrypter)
			require.NoError(t, err)
			assert.NotNil(t, msg.PlainText)
			assert.Nil(t, msg.CipherText)
			assert.Equal(t, []byte("secret data"), msg.PlainText)
		})
	})

	t.Run("encrypt fails on secret generation", func(t *testing.T) {
		msg.PlainText = []byte("data")
		failingEncrypter := &mockEncrypter{secretFail: true}
		err := msg.Encrypt(randy, *recipientPubKey, failingEncrypter)
		assert.Error(t, err)
	})

	t.Run("encrypt fails on symmetric encryption", func(t *testing.T) {
		msg.PlainText = []byte("data")
		failingEncrypter := &mockEncrypter{encFail: true}
		err := msg.Encrypt(randy, *recipientPubKey, failingEncrypter)
		assert.Error(t, err)
	})

	t.Run("decrypt fails", func(t *testing.T) {
		msg.CipherText = []byte("encrypted_data")
		failingDecrypter := &mockDecrypter{shouldFail: true}
		err := msg.Decrypt(failingDecrypter)
		assert.Error(t, err)
	})
}

func TestMessage_SignVerify(t *testing.T) {
	msg := &Message{PlainText: []byte("sign me"), Nonce: []byte("nonce")}
	signer := &mockSigner{}
	verifier := &mockVerifier{}
	pubKey := []byte("pubkey")

	t.Run("successful sign", func(t *testing.T) {
		err := msg.Sign(signer)
		require.NoError(t, err)
		assert.NotNil(t, msg.Signature)

		t.Run("successful verify", func(t *testing.T) {
			isValid := msg.Verify(pubKey, verifier)
			assert.True(t, isValid)
		})

		t.Run("verify fails on bad signature", func(t *testing.T) {
			originalSig := msg.Signature
			msg.Signature = []byte("bad sig")
			isValid := msg.Verify(pubKey, verifier)
			assert.False(t, isValid)
			msg.Signature = originalSig // restore
		})

		t.Run("verify fails with failing verifier", func(t *testing.T) {
			failingVerifier := &mockVerifier{shouldFail: true}
			isValid := msg.Verify(pubKey, failingVerifier)
			assert.False(t, isValid)
		})
	})

	t.Run("sign fails on digest error", func(t *testing.T) {
		invalidMsg := &Message{}
		err := invalidMsg.Sign(signer)
		assert.Error(t, err)
	})

	t.Run("sign fails on signer error", func(t *testing.T) {
		failingSigner := &mockSigner{shouldFail: true}
		err := msg.Sign(failingSigner)
		assert.Error(t, err)
	})

	t.Run("verify returns false on digest error", func(t *testing.T) {
		invalidMsg := &Message{}
		isValid := invalidMsg.Verify(pubKey, verifier)
		assert.False(t, isValid)
	})
}

func TestMessage_Sign(t *testing.T) {
	alice := alice(t)
	bob := bob(t)
	randy := dRand(t, 7)

	t.Run("empty message", func(t *testing.T) {
		msg := NewMessage(randy)
		err := msg.Sign(alice) // alice signs it
		assert.ErrorContains(t, err, "neither encrypted nor plain")
	})

	t.Run("happy path", func(t *testing.T) {
		msg := NewMessage(randy)
		msg.PlainText = []byte("hello world")
		err := msg.Sign(alice)
		assert.NoError(t, err)
		good := msg.Verify(alice.PublicKey().Signing(), bob) // bob verifies it
		assert.True(t, good)
	})

}

func TestMessage_Validate_Linear(t *testing.T) {
	msg := NewMessage(nil)
	err := msg.Validate()
	assert.Error(t, err)
	msg.Nonce = []byte("123")
	err = msg.Validate()
	assert.ErrorContains(t, err, "neither encrypted nor plain")
	msg.PlainText = []byte("hello world")
	assert.True(t, msg.IsPlain())
	assert.False(t, msg.IsEncrypted())
	msg.CipherText = []byte("i am cipher-text")
	err = msg.Validate()
	assert.True(t, msg.IsPlain())
	assert.True(t, msg.IsEncrypted())
	assert.Error(t, err)
	msg.PlainText = nil
	msg.Nonce = nil
	err = msg.Validate()
	assert.ErrorContains(t, err, "no nonce")
	msg.PlainText = []byte("hello world")
	msg.CipherText = nil
	msg.Signature = []byte("i am a signature")
}

func TestMessage_Body(t *testing.T) {
	t.Run("plain message", func(t *testing.T) {
		msg := &Message{PlainText: []byte("plain"), Nonce: []byte("nonce")}
		assert.Equal(t, []byte("plain"), msg.Body())
		assert.True(t, msg.IsPlain())
		assert.False(t, msg.IsEncrypted())
	})
	t.Run("encrypted message", func(t *testing.T) {
		msg := &Message{CipherText: []byte("ciph"), Nonce: []byte("nonce")}
		assert.Equal(t, []byte("ciph"), msg.Body())
		assert.False(t, msg.IsPlain())
		assert.True(t, msg.IsEncrypted())
	})
	t.Run("panics on invalid message", func(t *testing.T) {
		msg := &Message{}
		assert.Panics(t, func() {
			msg.Body()
		})
	})
}

func TestMessage_PEM(t *testing.T) {

	sm := smap.LexicalFrom(map[string]string{"pemType": "CUSTOM", "foo": "bar"})
	bin, err := sm.MarshalBinary()
	assert.NoError(t, err)

	msg := &Message{
		PlainText:    []byte("pem test"),
		AAD:          bin,
		Nonce:        []byte("123456789012"),
		EphemeralKey: []byte("ephkey"),
		Signature:    []byte("siggy"),
	}

	msgWithBinaryAAD := &Message{
		PlainText:    []byte("pem test"),
		AAD:          []byte("hello aad."),
		Nonce:        []byte("123456789012"),
		EphemeralKey: []byte("ephkey"),
		Signature:    []byte("siggy"),
	}

	t.Run("round-trip", func(t *testing.T) {
		pemBytes, err := msg.MarshalPEM()
		require.NoError(t, err)
		require.NotEmpty(t, pemBytes)

		// Check PEM block content
		block, rest := pem.Decode(pemBytes)
		require.NotNil(t, block)
		assert.Empty(t, rest)
		assert.Equal(t, "CUSTOM", block.Type)
		assert.Equal(t, "bar", block.Headers["foo"])

		newMsg := &Message{}
		err = newMsg.UnmarshalPEM(pemBytes)
		require.NoError(t, err)
		assert.Equal(t, msg.PlainText, newMsg.PlainText)
		assert.Equal(t, msg.Nonce, newMsg.Nonce)
		assert.Equal(t, msg.EphemeralKey, newMsg.EphemeralKey)
		assert.Equal(t, msg.Signature, newMsg.Signature)

		// why does this fail?
		assert.Equal(t, string(msg.AAD), string(newMsg.AAD))
	})

	t.Run("encrypted round-trip", func(t *testing.T) {
		encMsg := &Message{
			CipherText: []byte("encrypted pem"),
			AAD:        mustMarshal(map[string]string{"foo": "bar"}),
			Nonce:      []byte("nonce-enc"),
		}
		pemBytes, err := encMsg.MarshalPEM()
		require.NoError(t, err)

		block, _ := pem.Decode(pemBytes)
		assert.Equal(t, "ORACLE ENCRYPTED MESSAGE", block.Type)

		newMsg := &Message{}
		err = newMsg.UnmarshalPEM(pemBytes)
		require.NoError(t, err)
		assert.Equal(t, encMsg.CipherText, newMsg.CipherText)
		assert.Nil(t, newMsg.PlainText)
		assert.Equal(t, encMsg.Nonce, newMsg.Nonce)
	})

	t.Run("marshalpem fails on invalid message", func(t *testing.T) {
		invalidMsg := &Message{}
		_, err := invalidMsg.MarshalPEM()
		assert.Error(t, err)
	})

	t.Run("unmarshalpem fails on bad data", func(t *testing.T) {
		msg := &Message{}
		err := msg.UnmarshalPEM([]byte("not pem"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not decode PEM block")
	})

	t.Run("reconstitute fails on bad hex", func(t *testing.T) {
		block := &pem.Block{
			Type:  "TEST",
			Bytes: []byte("data"),
			Headers: map[string]string{
				"nonce": "bad-hex",
			},
		}
		msg := &Message{}
		err := msg.reconstituteFromPEM(block)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not decode nonce")
	})

	t.Run("message with non-mappable AAD", func(t *testing.T) {
		p := msgWithBinaryAAD.ToPEM()
		assert.Len(t, p.Headers, 4)
	})

	t.Run("unmarshal a PEM with a signature that can't be decoded", func(t *testing.T) {
		bin, err := os.ReadFile("../testdata/signed_message_with_bad_sig.pem")
		require.NoError(t, err)
		assert.NotNil(t, bin)
		msg := &Message{}
		err = msg.UnmarshalPEM(bin)
		assert.ErrorContains(t, err, "could not decode signature")
	})

}

type withBytes struct{}

func (w withBytes) Bytes() []byte { return []byte("from_bytes") }

type withMarshaler struct{}

func (w withMarshaler) MarshalBinary() ([]byte, error) { return []byte("from_marshaler"), nil }

func TestAsBytes(t *testing.T) {
	t.Run("from []byte", func(t *testing.T) {
		b := []byte("hello")
		res, err := asBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, b, res)
	})

	t.Run("from Bytes() method", func(t *testing.T) {

		res, err := asBytes(withBytes{})
		assert.NoError(t, err)
		assert.Equal(t, []byte("from_bytes"), res)
	})

	t.Run("from BinaryMarshaler", func(t *testing.T) {

		res, err := asBytes(withMarshaler{})
		assert.NoError(t, err)
		assert.Equal(t, []byte("from_marshaler"), res)
	})

	t.Run("from other binary type", func(t *testing.T) {
		var i int32 = 12345
		res, err := asBytes(i)
		assert.NoError(t, err)
		expected := make([]byte, 4)
		binary.LittleEndian.PutUint32(expected, 12345)
		assert.Equal(t, expected, res)
	})

	t.Run("unsupported type returns error", func(t *testing.T) {
		_, err := asBytes(make(chan int)) // a channel
		assert.Error(t, err)
	})

	t.Run("Byter", func(t *testing.T) {
		d := deterministicReader(4)
		k := delphi.NewKey(d)
		a, err := asBytes(k)
		assert.NoError(t, err)
		assert.Equal(t, k.Bytes(), a)
	})

	t.Run("plain old byte-slice", func(t *testing.T) {
		b1 := []byte("hello world")
		b2, err := asBytes(b1)
		assert.NoError(t, err)
		assert.Equal(t, b1, b2)
	})

	t.Run("custom type whose underlying type is a byte-slice", func(t *testing.T) {
		type custard []byte
		b1 := custard("hello world")
		b2, err := asBytes(b1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, b1, b2)
	})

	t.Run("custom type whose underlying type is something else", func(t *testing.T) {
		type custard string
		b1 := custard("hello world")
		b2, err := asBytes(b1)
		assert.Error(t, err)
		assert.Nil(t, b2)
	})

	t.Run("a binaryMarshaler", func(t *testing.T) {
		t1 := time.Date(2023, 12, 25, 15, 30, 45, 123456789, time.UTC)
		data, err := asBytes(t1)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
		var t2 time.Time
		err = t2.UnmarshalBinary(data)
		assert.NoError(t, err)
		assert.Equal(t, t1, t2)
	})

}

func mustMarshal(v any) []byte {

	switch v := v.(type) {
	case map[string]string:
		sm := smap.LexicalFrom(v)
		b, err := sm.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return b
	case []byte:
		return v
	case string:
		return []byte(v)
	case smap.LexicalStableMap[string, string]:
		b, err := v.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return b
	default:
		panic(fmt.Errorf("unknown type: %T", v))
	}

}

//func mustUnmarshal(b []byte) map[string]string {
//	m := make(map[string]string)
//	err := msgpack.Unmarshal(b, &m)
//	if err != nil {
//		panic(err)
//	}
//	return m
//}

type deterministicReader byte

func (d deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(d)
	}
	return len(p), nil
}

// dRand produces a deterministic randomness generator.
func dRand(t testing.TB, i byte) io.Reader {
	t.Helper()
	return deterministicReader(i)
}

func alice(t *testing.T) delphi.KeyPair {
	t.Helper()
	randy := dRand(t, 3)
	return delphi.NewKeyPair(randy)
}

func bob(t *testing.T) delphi.KeyPair {
	t.Helper()
	randy := dRand(t, 4)
	return delphi.NewKeyPair(randy)
}
func TestMessage_Encrypt(t *testing.T) {
	randy := dRand(t, 7)
	alice := alice(t)
	bob := bob(t)
	msg := NewMessage(randy)
	msg.PlainText = []byte("hello world")
	err := msg.Encrypt(randy, bob.PublicKey(), alice)
	assert.NoError(t, err)
	assert.Nil(t, msg.PlainText)
	assert.NotNil(t, msg.CipherText)
	err = msg.Decrypt(bob)
	assert.NoError(t, err)
	assert.NotNil(t, msg.PlainText)
	assert.Equal(t, []byte("hello world"), msg.PlainText)
}

func TestMessage_Serialize(t *testing.T) {

	t.Run("simple plain", func(t *testing.T) {
		msg1 := NewMessage(nil)
		msg1.PlainText = []byte("hello world")
		bin := msg1.Serialize()
		msg2 := new(Message)
		msg2.Deserialize(bin)
		assert.Equal(t, msg1.PlainText, msg2.PlainText)
	})

	t.Run("bad binary", func(t *testing.T) {
		assert.Panics(t, func() {
			msg3 := new(Message)
			msg3.Deserialize([]byte("this is not valid binary encoding."))
		})
	})

}

func FuzzMessage_Serialize(f *testing.F) {
	f.Add(
		[]byte("plain text"),
		[]byte("cipher text"),
		[]byte("AAD"),
		[]byte("nonce"),
		[]byte("ephemeral key"),
		[]byte("signature"),
	)
	f.Fuzz(func(t *testing.T, plain []byte, ciph []byte, nonce []byte, aad []byte, sig []byte, eph []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Error(r)
			}
		}()
		m := new(Message)
		m.PlainText = plain
		m.Nonce = nonce
		m.CipherText = ciph
		m.Signature = sig
		m.AAD = aad
		m.EphemeralKey = eph
		_ = m.Serialize()
	})
}
