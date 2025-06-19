package goracle

import (
	"iter"

	stablemap "github.com/sean9999/go-stable-map"
)

type store[K comparable, V any] interface {
	Entries() iter.Seq2[K, V]
	Get(K) (V, bool)
	Set(K, V) error
	Delete(K) error
	AsMap() map[K]V
}

type PeerStore = store[string, *Peer]

// type PeerStore interface {
// 	Entries() iter.Seq2[string, Peer]
// 	Get(string) (Peer, bool)
// 	Set(string, Peer) error
// 	Delete(string) error
// }

var _ PeerStore = (*peerStore)(nil)

type peerStore = stablemap.StableMap[string, *Peer]
