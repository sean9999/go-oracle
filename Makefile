BUILD_FOLDER=dist
BINARY_NAME=goracle
BIN_FOLDER=~/.local/bin
REPO=github.com/sean9999/go-oracle
CLI_LOCATION=cmd/goracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)

.PHONY: test

info:
	echo REPO is ${REPO} and SEMVER is ${SEMVER}

build:
	go build -v -o ./${BUILD_FOLDER}/${BINARY_NAME} -ldflags="-X 'main.Version=${SEMVER}'" ${CLI_LOCATION}/**.go

tidy:
	go mod tidy

install:
	cp -f ${BUILD_FOLDER}/${BINARY_NAME} ${BIN_FOLDER}/
	mkdir -p ${HOME}/.config/goracle
	touch ${HOME}/.config/goracle/conf.toml

clean:
	go clean
	rm ${BUILD_FOLDER}/${BINARY_NAME}

publish:
	GOPROXY=proxy.golang.org go list -m ${REPO}@${SEMVER}