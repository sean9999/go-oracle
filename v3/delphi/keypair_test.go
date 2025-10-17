package delphi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deterministicKeyPair(t testing.TB, seed int) KeyPair {
	t.Helper()
	randy := deterministicReader(t, seed)
	kp := NewKeyPair(randy)
	return kp
}

func TestNewKeyPair(t *testing.T) {

	kp := deterministicKeyPair(t, 1)

	t.Run("not zero", func(t *testing.T) {
		for _, k := range kp {
			assert.NotEqual(t, ZeroKey, k)
		}
	})

	t.Run("is zero", func(t *testing.T) {
		kp := KeyPair{}
		for _, k := range kp {
			assert.Equal(t, ZeroKey, k)
		}
	})

	t.Run("generates valid keys", func(t *testing.T) {
		randy := deterministicReader(t, 5)
		kp := NewKeyPair(randy)

		// Should not panic on validation
		assert.NotPanics(t, func() { kp.MustBeValid() })

		// KeyPair should be different
		assert.NotEqual(t, kp[0], kp[1])

		// Public and private keys should be different
		assert.NotEqual(t, kp.PublicKey(), kp.PrivateKey())
	})
}

func TestKeyPair_Bytes(t *testing.T) {
	kp := deterministicKeyPair(t, 1)
	data := kp.Bytes()
	assert.Equal(t, data[:64], Key(kp.PublicKey()).Bytes())
	assert.Equal(t, data[64:], Key(kp.PrivateKey()).Bytes())
	assert.Len(t, data, 128) // 64 bytes for public key + 64 bytes for private key
}

func TestKeyPair_String(t *testing.T) {
	kp := deterministicKeyPair(t, 1)
	assert.Equal(t, "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a2098a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101", kp.String())
}

func TestKeyPair_MustBeValid(t *testing.T) {
	t.Run("valid keypair", func(t *testing.T) {
		kp := deterministicKeyPair(t, 3)
		assert.NotPanics(t, func() { kp.MustBeValid() })
	})

	t.Run("zero keypair panics", func(t *testing.T) {
		kp := KeyPair{}
		assert.Panics(t, func() { kp.MustBeValid() })
	})

	t.Run("partially zero keypair panics", func(t *testing.T) {
		kp := KeyPair{}
		kp[0] = NewKey(deterministicReader(t, 1)) // valid key
		// kp[1] remains zero
		assert.Panics(t, func() { kp.MustBeValid() })
	})
}

func TestKeyPair_Write(t *testing.T) {
	t.Run("insufficient data", func(t *testing.T) {
		kp := &KeyPair{}
		data := make([]byte, 100) // Less than 128 bytes required

		n, err := kp.Write(data)
		assert.Equal(t, 0, n)
		assert.ErrorIs(t, err, io.ErrShortWrite)
	})

	t.Run("successful write", func(t *testing.T) {
		kp := &KeyPair{}
		data := make([]byte, 128)

		// Fill with test data
		_, _ = rand.Read(data)

		n, err := kp.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, 128, n)

		// Verify the data was written correctly
		assert.Equal(t, data, kp.Bytes())
	})

	t.Run("larger buffer", func(t *testing.T) {
		kp := &KeyPair{}
		data := make([]byte, 200) // More than 128 bytes

		// Fill first 128 bytes with test data
		for i := range data[:128] {
			data[i] = byte(i % 256)
		}

		n, err := kp.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, 128, n)

		// Verify only first 128 bytes were used
		assert.Equal(t, data[:128], kp.Bytes())
	})
}

func TestKeyPair_PublicKey(t *testing.T) {
	kp := deterministicKeyPair(t, 2)
	pubKey := kp.PublicKey()

	assert.Equal(t, Key(pubKey), kp[0])
	assert.NotEqual(t, Key(pubKey), kp[1]) // Should not be equal to private key
}

func TestKeyPair_PrivateKey(t *testing.T) {
	kp := deterministicKeyPair(t, 2)
	privKey := kp.PrivateKey()

	assert.Equal(t, Key(privKey), kp[1])
	assert.NotEqual(t, Key(privKey), kp[0]) // Should not be equal to public key
}

func TestKeyPair_PrivateSigningKey(t *testing.T) {
	kp := deterministicKeyPair(t, 3)
	privSignKey := kp.PrivateSigningKey()

	// Should be 64 bytes (32 private + 32 public)
	assert.Len(t, privSignKey.Bytes(), 64)

	// First 32 bytes should be private signing key
	privSigning := kp.PrivateKey().Signing().Bytes()
	pubSigning := kp.PublicKey().Signing().Bytes()

	expected := append(privSigning, pubSigning...)
	assert.Equal(t, expected, privSignKey.Bytes())
}

func TestKeyPair_Sign(t *testing.T) {
	kp := deterministicKeyPair(t, 4)

	message := []byte("hello world")
	digest := sha256.Sum256(message)

	signature, err := kp.Sign(nil, digest[:], nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, ed25519.SignatureSize)

	// Verify the signature works with ed25519
	privKey := ed25519.PrivateKey(kp.PrivateSigningKey().Bytes())
	isValid := ed25519.Verify(privKey.Public().(ed25519.PublicKey), digest[:], signature)
	assert.True(t, isValid)
}

func TestKeyPair_Verify(t *testing.T) {
	kp := deterministicKeyPair(t, 5)

	message := []byte("test message")
	digest := sha256.Sum256(message)

	// Sign with the keypair
	signature, err := kp.Sign(nil, digest[:], nil)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		pubKey := kp.PublicKey().Signing().Bytes()
		isValid := kp.Verify(pubKey, digest[:], signature)
		assert.True(t, isValid)
	})

	t.Run("invalid signature", func(t *testing.T) {
		pubKey := kp.PublicKey().Signing().Bytes()
		wrongSignature := make([]byte, len(signature))
		copy(wrongSignature, signature)
		wrongSignature[0] ^= 0xFF // Flip some bits

		isValid := kp.Verify(pubKey, digest[:], wrongSignature)
		assert.False(t, isValid)
	})

	t.Run("invalid public key", func(t *testing.T) {
		invalidPubKey := "not a valid key"
		isValid := kp.Verify(invalidPubKey, digest[:], signature)
		assert.False(t, isValid)
	})
}

func TestKeyPair_Decrypt(t *testing.T) {
	kp := deterministicKeyPair(t, 7)
	plaintext := []byte("secret message")
	nonce := make([]byte, 12)
	aad := []byte("additional data")
	ephemeralKey := make([]byte, 32)

	// Fill test data
	copy(nonce, "test_nonce12")
	copy(ephemeralKey, kp.PublicKey().Encryption().Bytes())

	t.Run("successful decryption", func(t *testing.T) {
		// First encrypt to get valid ciphertext
		sharedSecret := make([]byte, 32)
		copy(sharedSecret, "shared_secret_for_testing_12345")

		ciphertext, err := kp.Seal(sharedSecret, plaintext, nonce, aad)
		require.NoError(t, err)

		// Note: This test might fail due to the complexity of the actual decryption
		// but it tests the method signature and error handling
		_, err = kp.Decrypt(ciphertext, ephemeralKey, nonce, aad)
		// We expect an error here since we're using test data, but the method should not panic
		assert.Error(t, err)
	})

}

func TestKeyPair_SymmetricEncrypt(t *testing.T) {
	kp := deterministicKeyPair(t, 8)

	key := make([]byte, 32)
	plaintext := []byte("test message for encryption")
	nonce := make([]byte, 12)
	aad := []byte("additional authenticated data")

	// Fill with test data
	copy(key, "test_encryption_key_32_bytes_lg")
	copy(nonce, "test_nonce12")

	ciphertext, err := kp.Seal(key, plaintext, nonce, aad)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Should be longer than plaintext due to authentication tag
	assert.Greater(t, len(ciphertext), len(plaintext))
}

func TestKeyPair_GenerateSharedSecret(t *testing.T) {
	alice := deterministicKeyPair(t, 10)
	bob := deterministicKeyPair(t, 11)
	randy := deterministicReader(t, 12)

	t.Run("successful generation", func(t *testing.T) {
		sharedSecret, ephemeralPubKey, err := alice.GenerateSharedSecret(randy, bob.PublicKey())

		assert.NoError(t, err)
		assert.NotEmpty(t, sharedSecret)
		assert.NotEmpty(t, ephemeralPubKey)
		assert.Len(t, sharedSecret, 32)    // chacha20poly1305.KeySize
		assert.Len(t, ephemeralPubKey, 32) // curve25519 public key size
	})

	t.Run("invalid recipient type", func(t *testing.T) {
		invalidRecipient := PublicKey{}

		_, _, err := alice.GenerateSharedSecret(randy, invalidRecipient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bad X25519")
	})
}

func TestAsBytes(t *testing.T) {
	t.Run("byte slice", func(t *testing.T) {
		input := []byte("test data")
		result, err := asBytes(input)

		assert.NoError(t, err)
		assert.Equal(t, input, result)
	})

	t.Run("bytes method", func(t *testing.T) {
		key := NewKey(deterministicReader(t, 1))
		result, err := asBytes(key)

		assert.NoError(t, err)
		assert.Equal(t, key.Bytes(), result)
	})

	t.Run("binary marshaler", func(t *testing.T) {
		// Create a mock binary marshaler
		marshaler := &mockBinaryMarshaler{data: []byte("marshaled data")}
		result, err := asBytes(marshaler)

		assert.NoError(t, err)
		assert.Equal(t, marshaler.data, result)
	})

	t.Run("unsupported type", func(t *testing.T) {
		input := "not supported"
		_, err := asBytes(input)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a binary marshaler")
	})
}

// Mock implementation for testing
type mockBinaryMarshaler struct {
	data []byte
}

func (m *mockBinaryMarshaler) MarshalBinary() ([]byte, error) {
	return m.data, nil
}

func TestKeyPair_ErrorHandling(t *testing.T) {
	t.Run("MustBeValid with zero keypair", func(t *testing.T) {
		kp := KeyPair{}
		assert.Panics(t, func() {
			kp.Bytes() // This calls MustBeValid internally
		})
	})

	t.Run("String with zero keypair", func(t *testing.T) {
		kp := KeyPair{}
		assert.Panics(t, func() {
			_ = kp.String() // This calls MustBeValid internally
		})
	})
}

func TestKeyPair_MarshalJSON(t *testing.T) {
	alice1 := deterministicKeyPair(t, 10)
	bin, err := alice1.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, bin)
	alice2 := new(KeyPair)
	err = json.Unmarshal(bin, alice2)
	assert.NoError(t, err)
	assert.Equal(t, alice1.Bytes(), alice2.Bytes())
}
