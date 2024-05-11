REPO=github.com/sean9999/go-oracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)

info:
	echo REPO is ${REPO} and SEMVER is ${SEMVER}

bin/goracle:
	go build -v -o bin/goracle -ldflags="-X 'main.Version=${SEMVER}'" cmd/goracle/**.go
	
bin/pemreader:	
	go build -v -o bin/pemreader -ldflags="-X 'main.Version=${SEMVER}'" cmd/pemreader/**.go

tidy:
	go mod tidy

install:
	go install ./cmd/goracle 
	go install ./cmd/pemreader
	mkdir -p ${HOME}/.config/goracle
	touch ${HOME}/.config/goracle/conf.toml

clean:
	go clean
	go clean -modcache
	rm bin/*

pkgsite:
	if [ -z "$$(command -v pkgsite)" ]; then go install golang.org/x/pkgsite/cmd/pkgsite@latest; fi

docs: pksite
	pkgsite -open .

publish:
	GOPROXY=https://goproxy.io,direct go list -m ${REPO}@${SEMVER}

test:
	go test ./...

.PHONY: x
