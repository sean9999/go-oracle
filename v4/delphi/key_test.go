package delphi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey_MustBeValid(t *testing.T) {

	t.Run("zeroKey is invalid", func(t *testing.T) {
		assert.Panics(t, func() { ZeroKey.MustBeValid() })
	})

	t.Run("this non zero key should be valid", func(t *testing.T) {
		randy := deterministicReader(t, 5)
		k := NewKey(randy)
		assert.NotPanics(t, func() { k.MustBeValid() })
	})
}

func TestKey_Bytes(t *testing.T) {
	randy := deterministicReader(t, 5)
	k1 := NewKey(randy)
	bin := k1.Bytes()
	k2, err := KeyFromBytes(bin)
	assert.NoError(t, err)
	assert.Equal(t, k1.String(), k2.String())
}

func TestKey_JSON(t *testing.T) {
	randy := deterministicReader(t, 5)
	k1 := NewKey(randy)

	j, err := k1.MarshalJSON()
	assert.NoError(t, err)

	k2 := new(Key)
	err = k2.UnmarshalJSON(j)
	assert.NoError(t, err)

	assert.True(t, k1.Equal(*k2))

}

func TestKeyFromBytes(t *testing.T) {

	t.Run("zero byte-slice produces zeroKey, which is an error", func(t *testing.T) {
		data := make([]byte, subKeySize*2)
		k, err := KeyFromBytes(data)
		assert.ErrorIs(t, err, ErrZeroKey)
		assert.True(t, k.Equal(ZeroKey))
	})

	t.Run("byte-slice too small", func(t *testing.T) {
		data := make([]byte, 21)
		data[5] = 5
		k, err := KeyFromBytes(data)
		assert.Error(t, err)
		assert.True(t, k.Equal(ZeroKey))
	})

	t.Run("byte-slice too big", func(t *testing.T) {
		data := make([]byte, 2100)
		data[5] = 5
		k, err := KeyFromBytes(data)
		assert.Error(t, err)
		assert.True(t, k.Equal(ZeroKey))
	})

	t.Run("happy path", func(t *testing.T) {
		data := make([]byte, 64)
		randy := deterministicReader(t, 3)
		_, _ = randy.Read(data)
		k, err := KeyFromBytes(data)
		assert.NoError(t, err)
		assert.False(t, k.Equal(ZeroKey))
		assert.Equal(t, "03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303", k.String())
	})

}

func TestKey_Write(t *testing.T) {
	t.Run("bad length", func(t *testing.T) {
		k := new(Key)
		data := []byte("i am not long enough.")
		i, err := k.Write(data)
		assert.Error(t, err)
		assert.Zero(t, i)
	})

	t.Run("happy path", func(t *testing.T) {
		k := new(Key)
		data := make([]byte, 64)
		randy := deterministicReader(t, 7)
		_, _ = randy.Read(data)

		i, err := k.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, 64, i)
		assert.Equal(t, data, k.Bytes())
	})

	t.Run("exact size", func(t *testing.T) {
		k := new(Key)
		data := make([]byte, subKeySize*2)
		for i := range data {
			data[i] = byte(i)
		}

		i, err := k.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, subKeySize*2, i)
		assert.Equal(t, data, k.Bytes())
	})

	t.Run("larger slice", func(t *testing.T) {
		k := new(Key)
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i)
		}

		i, err := k.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, subKeySize*2, i)
		assert.Equal(t, data[:64], k.Bytes())
	})
}

func Test_KeyFromString(t *testing.T) {

}

func TestKey_Read(t *testing.T) {

	randy := deterministicReader(t, 5)

	sixtyFourBytesOfRandomData := make([]byte, 64)
	_, err := rand.Read(sixtyFourBytesOfRandomData)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		k            Key
		data         []byte
		bytesWritten int
		err          error
		panics       bool
	}{
		{
			name:         "data size. too small",
			k:            NewKey(randy),
			data:         make([]byte, 32),
			bytesWritten: 0,
			err:          ErrWrongSize,
			panics:       false,
		},
		{
			name:         "zero key should panic",
			k:            Key{},
			data:         make([]byte, 64),
			bytesWritten: 64,
			err:          ErrZeroKey,
			panics:       true,
		},
		{
			name:         "happy path",
			k:            NewKey(randy),
			data:         make([]byte, 64),
			bytesWritten: 64,
			err:          io.EOF,
		},
		{
			name:         "more than enough bytes should still be happy",
			k:            NewKey(randy),
			data:         make([]byte, 300),
			bytesWritten: 64,
			err:          io.EOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() {
					_, _ = tt.k.Read(tt.data)
				})
			} else {
				bytesWritten, err := tt.k.Read(tt.data)
				assert.Equal(t, tt.bytesWritten, bytesWritten)
				assert.ErrorIs(t, err, tt.err)
				if err == nil || errors.Is(err, io.EOF) {
					//	assert that the read operation worked by comparing bytes
					assert.Equal(t, tt.k.Bytes(), tt.data[:64])
				}
			}
		})
	}
}

func TestKeyFromString(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    Key
		wantErr error
	}{
		{
			name: "invalid hex",
			args: args{
				s: "i am invalid hex.",
			},
			want:    Key{},
			wantErr: new(hex.InvalidByteError),
		},
		{
			name: "bad length",
			args: args{
				s: "F00DE4",
			},
			want:    Key{},
			wantErr: io.EOF,
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			got, err := KeyFromString(tt.args.s)

			assert.ErrorAs(t, err, &tt.wantErr)

			assert.Equalf(t, tt.want, got, "KeyFromString(%v)", tt.args.s)
		})
	}
}

func TestKey_Equal(t *testing.T) {
	alice := NewKey(deterministicReader(t, 1))
	bob := NewKey(deterministicReader(t, 2))
	alice2, err := KeyFromBytes(alice.Bytes())
	assert.NoError(t, err)
	assert.True(t, alice.Equal(alice2))
	assert.False(t, alice.Equal(bob))
}

func TestPrivateKey_Methods(t *testing.T) {
	randy := deterministicReader(t, 7)
	k := NewKey(randy)
	privKey := PrivateKey(k)

	t.Run("Encryption", func(t *testing.T) {
		encSubKey := privKey.Encryption()
		assert.Equal(t, k[0], encSubKey)
	})

	t.Run("Signing", func(t *testing.T) {
		sigSubKey := privKey.Signing()
		assert.Equal(t, k[1], sigSubKey)
	})
}

// Test PublicKey and PrivateKey type methods
func TestPublicKey_Methods(t *testing.T) {
	randy := deterministicReader(t, 5)
	k := NewKey(randy)
	pubKey := PublicKey(k)

	t.Run("Encryption", func(t *testing.T) {
		encSubKey := pubKey.Encryption()
		assert.Equal(t, k[0], encSubKey)
	})

	t.Run("Signing", func(t *testing.T) {
		sigSubKey := pubKey.Signing()
		assert.Equal(t, k[1], sigSubKey)
	})

	t.Run("Bytes", func(t *testing.T) {
		bytes := pubKey.Bytes()
		assert.Equal(t, k.Bytes(), bytes)
	})
}

func TestNewKey(t *testing.T) {
	t.Run("with valid reader", func(t *testing.T) {
		randy := deterministicReader(t, 3)
		k := NewKey(randy)
		assert.False(t, k.Equal(ZeroKey))
		expected := "0303030303030303030303030303030303030303030303030303030303030303" +
			"0303030303030303030303030303030303030303030303030303030303030303"
		assert.Equal(t, expected, k.String())
	})

	t.Run("with nil reader", func(t *testing.T) {
		k := NewKey(nil)
		assert.Equal(t, ZeroKey, k)
	})
}

func TestKey_String(t *testing.T) {
	t.Run("zero key", func(t *testing.T) {
		k := ZeroKey
		expected := "0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000"
		assert.Equal(t, expected, k.String())
	})

	t.Run("non-zero key", func(t *testing.T) {
		k := NewKey(deterministicReader(t, 1))
		expected := "0101010101010101010101010101010101010101010101010101010101010101" +
			"0101010101010101010101010101010101010101010101010101010101010101"
		assert.Equal(t, expected, k.String())
	})
}

//func TestKey_Read(t *testing.T) {
//	alice := NewKey(dRand(t, 1))
//	buf := make([]byte, 64)
//	i, err := alice.Read(buf)
//	assert.NoError(t, err)
//	assert.Equal(t, buf[:i], alice.Bytes())
//	assert.Equal(t, 64, i)
//}
