package oracle

// This is a deterministic [io.Reader] for fake randomness.
type BunchOfZeros struct{}

func (dr *BunchOfZeros) Read(p []byte) (int, error) {
	output := make([]byte, len(p))
	return copy(p, output), nil
}
