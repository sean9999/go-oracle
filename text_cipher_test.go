package oracle_test

import (
	"testing/fstest"

	"github.com/sean9999/go-oracle"
)

const PHRASE = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of light, it was the season of darkness, it was the spring of hope, it was the winter of despair."
const MSG_LOCATION = "testdata/tale_of_two_cities.bin"

var testFileSystem = fstest.MapFS{
	MSG_LOCATION: &fstest.MapFile{},
}

var encryptedMsg = new(oracle.CipherText)
