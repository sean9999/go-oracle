package goracle

// fakeRand is a fake source of randomness.
// It just spits out the same byte over and over.
type fakeRand byte

func (f fakeRand) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = byte(f)
	}
	return len(data), nil
}
