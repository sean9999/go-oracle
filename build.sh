#!/bin/bash

SEMVER="$(git tag --sort=-version:refname | head -n 1)"

#	build the binary
go build -v \
    -ldflags="-s -w" \
	-ldflags="-X 'main.Version=$SEMVER'" \
	-o ./dist/magi \
    ./cli/magi/**.go
