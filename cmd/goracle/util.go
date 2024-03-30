package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/sean9999/go-oracle"
)

// a defect is an error with an exit code
type defect struct {
	Name        string
	Description string
	ExitCode    int
	Wraps       error
}

func (def defect) Error() string {
	return def.Description
}

// complain is the action taken when the main loop encounters a defect
func complain(def defect) {
	fmt.Fprintln(os.Stderr, def.Description)
	os.Exit(def.ExitCode)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return (err == nil)
}

func fileCanBeCreated(path string, perm fs.FileMode) (bool, error) {
	fd, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, perm)
	defer func() {
		fd.Close()
		os.Remove(path)
	}()
	return (err == nil), err
}

func isWellFormedConfig(path string) (bool, error) {

	fd, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer fd.Seek(0, 0)
	_, err = oracle.ConfigFrom(fd)
	if err != nil {
		return false, err
	}
	return true, nil

}

func configFileExistsAndIsWellFormed(path string) (*os.File, error) {
	if !fileExists(path) {
		return nil, os.ErrExist
	}
	_, err := isWellFormedConfig(path)
	if err != nil {
		return nil, err
	}
	fd, _ := os.Open(path)
	return fd, nil
}

func configFileDoesNotExistButCanBeCreated(path string) error {
	if fileExists(path) {
		return defect{"file exists", "file already exists", 7, os.ErrExist}
	}
	_, err := fileCanBeCreated(path, 0600)
	return err
}

func ConfigFromFileDescriptor(fd io.Reader) (oracle.Config, error) {
	if fd == nil {
		return oracle.ZeroConf, defect{"fd is nil", "file descriptor is nil", 11, errors.New("fd is nil")}
	}
	return oracle.ConfigFrom(fd)
}
