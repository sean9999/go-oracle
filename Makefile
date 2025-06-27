MODULE=github.com/sean9999/go-oracle
CONTAINER_IMAGE=docker.io/codemonk9999/oracle
SEMVER := $$(git tag --sort=-version:refname | head -n 1)
BRANCH := $$(git branch --show-current)
REF := $$(git describe --dirty --tags --always)
GOPROXY=proxy.golang.org

info:
	@printf "MODULE:\t%s\nSEMVER:\t%s\nBRANCH:\t%s\nREF:\t%s\nIMAGE:\t%s\n" $(MODULE) $(SEMVER) $(BRANCH) $(REF) $(CONTAINER_IMAGE)

tidy:
	go mod tidy

clean:
	go clean
	go clean -modcache
	rm -f ./bin/*

pkgsite:
	if [ -z "$$(command -v pkgsite)" ]; then go install golang.org/x/pkgsite/cmd/pkgsite@latest; fi

docs: pkgsite
	pkgsite -open .

publish:
	GOPROXY=https://${GOPROXY},direct go list -m ${MODULE}@${SEMVER}

bin/delphi:
	go build -o bin/delphi ./cmd/delphi

install:
	go install ./cmd/delphi

docker:
	docker build --no-cache -t ${CONTAINER_IMAGE}:${REF} \
	-t ${CONTAINER_IMAGE}:latest \
	-t ${CONTAINER_IMAGE}:${BRANCH} .

push:
	docker push ${CONTAINER_IMAGE}:${REF}
	docker push ${CONTAINER_IMAGE}:latest
	docker push ${CONTAINER_IMAGE}:${BRANCH}

test:
	go test -vet=all -race ./...

.PHONY: test

