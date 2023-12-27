#!/bin/sh

#   latest tag
version="$(git tag | tail -n 1)"

modulename="github.com/sean9999/go-oracle"

GOPROXY=proxy.golang.org go list -m ${modulename}@${version}
