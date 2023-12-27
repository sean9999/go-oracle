BUILD_FOLDER=dist
BINARY_NAME=magi
BIN_FOLDER=/usr/local/bin
REPO=github.com/sean9999/go-oracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)

.PHONY: test

info:
	echo REPO is ${REPO} and SEMVER is ${SEMVER}

build:
	go build -v -ldflags="-X 'main.Version=${SEMVER}' -X 'app/build.Time=$(date)'" -o ./${BUILD_FOLDER}/${BINARY_NAME}

docker-build:
	docker build -t ${REPO}:${SEMVER} .

docker-run:
	docker run -p 9001:9001 -v $${PWD}/public:/srv/public ${REPO}:${SEMVER}

run:
	go run *.go --dir=public --port=9443 

tidy:
	go mod tidy

vendor:
	go mod vendor

install:
	cp -f ${BUILD_FOLDER}/${BINARY_NAME} ${BIN_FOLDER}/

clean:
	go clean
	rm ${BUILD_FOLDER}/${BINARY_NAME}

publish:
	GOPROXY=proxy.golang.org go list -m ${REPO}@${SEMVER}