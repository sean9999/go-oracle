package oracle

import (
	"encoding/json"
	"oracle2/delphi"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerStore_MarshalJSON(t *testing.T) {
	t.Run("empty peerstore", func(t *testing.T) {
		ps := make(PeerStore)

		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// Should marshal to empty JSON object
		assert.JSONEq(t, "{}", string(data))
	})

	t.Run("single peer", func(t *testing.T) {
		ps := make(PeerStore)

		// Create a test key and Props
		key := delphi.NewKey(fakeRand(1))
		pubKey := delphi.PublicKey(key)
		testProps := Props{
			"name":     "Alice",
			"location": "Wonderland",
		}

		ps[pubKey] = testProps

		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// Parse the JSON to verify structure
		var result map[string]Props
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Should have one entry with the key as hex string
		assert.Len(t, result, 1)

		// Get the key (should be hex representation)
		var marshaledProps Props
		for k, v := range result {
			assert.Equal(t, pubKey.String(), k)
			marshaledProps = v
			break
		}

		assert.Equal(t, testProps, marshaledProps)
	})

	t.Run("multiple peers", func(t *testing.T) {
		ps := make(PeerStore)

		// Create multiple test keys and Props
		key1 := delphi.NewKey(fakeRand(1))
		key2 := delphi.NewKey(fakeRand(2))
		key3 := delphi.NewKey(fakeRand(3))

		pubKey1 := delphi.PublicKey(key1)
		pubKey2 := delphi.PublicKey(key2)
		pubKey3 := delphi.PublicKey(key3)

		ps[pubKey1] = Props{"name": "Alice", "role": "admin"}
		ps[pubKey2] = Props{"name": "Bob", "role": "user"}
		ps[pubKey3] = Props{"name": "Charlie", "role": "moderator"}

		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// Parse the JSON to verify structure
		var result map[string]Props
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Should have three entries
		assert.Len(t, result, 3)

		// Verify each key-value pair
		assert.Equal(t, Props{"name": "Alice", "role": "admin"}, result[pubKey1.String()])
		assert.Equal(t, Props{"name": "Bob", "role": "user"}, result[pubKey2.String()])
		assert.Equal(t, Props{"name": "Charlie", "role": "moderator"}, result[pubKey3.String()])
	})

	t.Run("peer with empty Props", func(t *testing.T) {
		ps := make(PeerStore)

		key := delphi.NewKey(fakeRand(4))
		pubKey := delphi.PublicKey(key)
		emptyProps := Props{}

		ps[pubKey] = emptyProps

		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// Parse and verify
		var result map[string]Props
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Len(t, result, 1)
		assert.Equal(t, emptyProps, result[pubKey.String()])
	})

	t.Run("peer with nil Props", func(t *testing.T) {
		ps := make(PeerStore)

		key := delphi.NewKey(fakeRand(5))
		pubKey := delphi.PublicKey(key)

		ps[pubKey] = nil

		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// Parse and verify - nil should be marshaled as null
		var result map[string]Props
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Len(t, result, 1)
		assert.Nil(t, result[pubKey.String()])
	})
}

func TestPeerStore_UnmarshalJSON(t *testing.T) {
	t.Run("empty JSON object", func(t *testing.T) {
		ps := make(PeerStore)

		err := ps.UnmarshalJSON([]byte("{}"))
		assert.NoError(t, err)
		assert.Len(t, ps, 0)
	})

	t.Run("single peer", func(t *testing.T) {
		ps := make(PeerStore)

		// Create expected key and Props
		key := delphi.NewKey(fakeRand(1))
		pubKey := delphi.PublicKey(key)
		expectedProps := Props{
			"name":     "Alice",
			"location": "Wonderland",
		}

		// Create JSON with hex key
		jsonData := map[string]Props{
			pubKey.String(): expectedProps,
		}
		data, err := json.Marshal(jsonData)
		require.NoError(t, err)

		err = ps.UnmarshalJSON(data)
		assert.NoError(t, err)

		assert.Len(t, ps, 1)
		assert.Equal(t, expectedProps, ps[pubKey])
	})

	t.Run("multiple peers", func(t *testing.T) {
		ps := make(PeerStore)

		// Create test data
		key1 := delphi.NewKey(fakeRand(1))
		key2 := delphi.NewKey(fakeRand(2))
		key3 := delphi.NewKey(fakeRand(3))

		pubKey1 := delphi.PublicKey(key1)
		pubKey2 := delphi.PublicKey(key2)
		pubKey3 := delphi.PublicKey(key3)

		props1 := Props{"name": "Alice", "role": "admin"}
		props2 := Props{"name": "Bob", "role": "user"}
		props3 := Props{"name": "Charlie", "role": "moderator"}

		jsonData := map[string]Props{
			pubKey1.String(): props1,
			pubKey2.String(): props2,
			pubKey3.String(): props3,
		}
		data, err := json.Marshal(jsonData)
		require.NoError(t, err)

		err = ps.UnmarshalJSON(data)
		assert.NoError(t, err)

		assert.Len(t, ps, 3)
		assert.Equal(t, props1, ps[pubKey1])
		assert.Equal(t, props2, ps[pubKey2])
		assert.Equal(t, props3, ps[pubKey3])
	})

	t.Run("invalid JSON", func(t *testing.T) {
		ps := make(PeerStore)

		err := ps.UnmarshalJSON([]byte("invalid json"))
		assert.Error(t, err)
	})

	t.Run("invalid hex key", func(t *testing.T) {
		ps := make(PeerStore)

		// JSON with invalid hex key
		jsonStr := `{"invalid_hex_key": {"name": "Alice"}}`

		err := ps.UnmarshalJSON([]byte(jsonStr))
		assert.Error(t, err)
	})

	t.Run("key too short", func(t *testing.T) {
		ps := make(PeerStore)

		// JSON with hex key that's too short
		jsonStr := `{"0102030405": {"name": "Alice"}}`

		err := ps.UnmarshalJSON([]byte(jsonStr))
		assert.Error(t, err)
	})

	t.Run("key too long", func(t *testing.T) {
		ps := make(PeerStore)

		// JSON with hex key that's too long
		longKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"
		jsonStr := `{"` + longKey + `": {"name": "Alice"}}`

		err := ps.UnmarshalJSON([]byte(jsonStr))
		assert.Error(t, err)
	})

	t.Run("zero key", func(t *testing.T) {
		ps := make(PeerStore)

		// JSON with zero key (all zeros)
		zeroKeyStr := "0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000"
		jsonStr := `{"` + zeroKeyStr + `": {"name": "Alice"}}`

		err := ps.UnmarshalJSON([]byte(jsonStr))
		// This should return an error since KeyFromString should fail for zero key
		assert.Error(t, err)
	})

	t.Run("empty Props", func(t *testing.T) {
		ps := make(PeerStore)

		key := delphi.NewKey(fakeRand(6))
		pubKey := delphi.PublicKey(key)

		jsonData := map[string]Props{
			pubKey.String(): {},
		}
		data, err := json.Marshal(jsonData)
		require.NoError(t, err)

		err = ps.UnmarshalJSON(data)
		assert.NoError(t, err)

		assert.Len(t, ps, 1)
		assert.Equal(t, Props{}, ps[pubKey])
	})

	t.Run("null Props", func(t *testing.T) {
		ps := make(PeerStore)

		key := delphi.NewKey(fakeRand(7))
		pubKey := delphi.PublicKey(key)

		jsonStr := `{"` + pubKey.String() + `": null}`

		err := ps.UnmarshalJSON([]byte(jsonStr))
		assert.NoError(t, err)

		assert.Len(t, ps, 1)
		assert.Nil(t, ps[pubKey])
	})
}

func TestPeerStore_RoundTrip(t *testing.T) {
	t.Run("marshal then unmarshal", func(t *testing.T) {
		// Create original peerstore
		original := make(PeerStore)

		key1 := delphi.NewKey(fakeRand(10))
		key2 := delphi.NewKey(fakeRand(11))
		key3 := delphi.NewKey(fakeRand(12))

		pubKey1 := delphi.PublicKey(key1)
		pubKey2 := delphi.PublicKey(key2)
		pubKey3 := delphi.PublicKey(key3)

		original[pubKey1] = Props{"name": "Alice", "role": "admin", "location": "NYC"}
		original[pubKey2] = Props{"name": "Bob", "role": "user"}
		original[pubKey3] = Props{}

		// Marshal
		data, err := original.MarshalJSON()
		require.NoError(t, err)

		// Unmarshal into new peerstore
		restored := make(PeerStore)
		err = restored.UnmarshalJSON(data)
		require.NoError(t, err)

		// Verify they're equal
		assert.Len(t, restored, len(original))
		for k, v := range original {
			assert.Equal(t, v, restored[k], "Props mismatch for key %s", k.String())
		}
	})

	t.Run("unmarshal then marshal", func(t *testing.T) {
		// Start with JSON data
		key1 := delphi.NewKey(fakeRand(13))
		key2 := delphi.NewKey(fakeRand(14))

		pubKey1 := delphi.PublicKey(key1)
		pubKey2 := delphi.PublicKey(key2)

		originalJSON := map[string]Props{
			pubKey1.String(): {"name": "Carol", "role": "moderator"},
			pubKey2.String(): {"name": "Dave", "role": "guest"},
		}

		originalData, err := json.Marshal(originalJSON)
		require.NoError(t, err)

		// Unmarshal
		ps := make(PeerStore)
		err = ps.UnmarshalJSON(originalData)
		require.NoError(t, err)

		// Marshal back
		restoredData, err := ps.MarshalJSON()
		require.NoError(t, err)

		// Parse both JSON strings and compare
		var original, restored map[string]Props
		err = json.Unmarshal(originalData, &original)
		require.NoError(t, err)
		err = json.Unmarshal(restoredData, &restored)
		require.NoError(t, err)

		assert.Equal(t, original, restored)
	})
}

func TestPeerStore_EdgeCases(t *testing.T) {
	t.Run("nil peerstore pointer", func(t *testing.T) {
		var ps *PeerStore = nil

		// This should panic or handle gracefully
		assert.Panics(t, func() {
			ps.UnmarshalJSON([]byte("{}"))
		})
	})

	t.Run("uninitialized peerstore", func(t *testing.T) {
		ps := PeerStore(nil)

		// MarshalJSON should work even with nil map
		data, err := ps.MarshalJSON()
		assert.NoError(t, err)
		assert.JSONEq(t, "{}", string(data))
	})

	t.Run("very large JSON", func(t *testing.T) {
		ps := make(PeerStore)

		// Create large Props
		largeProps := Props{}
		for i := 0; i < 1000; i++ {
			largeProps[string(rune(i))] = string(rune(i + 1000))
		}

		key := delphi.NewKey(fakeRand(99))
		pubKey := delphi.PublicKey(key)
		ps[pubKey] = largeProps

		// Should handle large data
		data, err := ps.MarshalJSON()
		assert.NoError(t, err)

		// And unmarshal back
		restored := make(PeerStore)
		err = restored.UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.Equal(t, largeProps, restored[pubKey])
	})
}

func TestPeerStore_JSONCompatibility(t *testing.T) {
	t.Run("standard json package compatibility", func(t *testing.T) {
		ps := make(PeerStore)
		key := delphi.NewKey(fakeRand(20))
		pubKey := delphi.PublicKey(key)
		ps[pubKey] = Props{"test": "value"}

		// Should work with standard json.Marshal
		data1, err := json.Marshal(ps)
		require.NoError(t, err)

		// Should be same as our custom MarshalJSON
		data2, err := ps.MarshalJSON()
		require.NoError(t, err)

		assert.JSONEq(t, string(data1), string(data2))

		// Should work with standard json.Unmarshal
		restored1 := make(PeerStore)
		err = json.Unmarshal(data1, &restored1)
		require.NoError(t, err)

		restored2 := make(PeerStore)
		err = restored2.UnmarshalJSON(data2)
		require.NoError(t, err)

		assert.Equal(t, restored1, restored2)
	})
}
