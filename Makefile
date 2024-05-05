REPO=github.com/sean9999/go-oracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)
SYSTEM_BINS=/usr/local/bin

.PHONY: test

info:
	echo REPO is ${REPO} and SEMVER is ${SEMVER}

build:
	go build -v -o bin/goracle -ldflags="-X 'main.Version=${SEMVER}'" cmd/goracle/**.go
	go build -v -o bin/pemreader -ldflags="-X 'main.Version=${SEMVER}'" cmd/pemreader/**.go

tidy:
	go mod tidy

install:
	go install ./cmd/goracle 
	go install ./cmd/pemreader
	mkdir -p ${HOME}/.config/goracle
	touch ${HOME}/.config/goracle/conf.json

clean:
	go clean
	rm bin/*

docs:
	pkgsite -open .

publish:
	GOPROXY=https://goproxy.io,direct go list -m ${REPO}@${SEMVER}
