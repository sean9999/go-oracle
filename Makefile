REPO=github.com/sean9999/go-oracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)
BRANCH := $$(git branch --show-current)
REF := $$(git describe --dirty --tags --always)

info:
	@printf "REPO:\t%s\nSEMVER:\t%s\nBRANCH:\t%s\nREF:\t%s\n" $(REPO) $(SEMVER) $(BRANCH) $(REF)

binaries: bin/goracle bin/pemreader

bin/goracle:
	go build -v -o bin/goracle -ldflags="-X 'main.Version=$(REF)'" cmd/goracle/**.go
	
bin/pemreader:	
	go build -v -o bin/pemreader -ldflags="-X 'main.Version=$(REF)'" cmd/pemreader/**.go

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

docs: pkgsite
	pkgsite -open .

publish:
	GOPROXY=https://goproxy.io,direct go list -m ${REPO}@${SEMVER}

test:
	git restore testdata
	go test ./...
	git restore testdata

.PHONY: test
