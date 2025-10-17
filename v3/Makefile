MODULE=github.com/sean9999/oracle2
CONTAINER_IMAGE=docker.io/codemonk9999/oracle2
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

test:
	go test ./...

vet:
	go vet ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated:"
	@echo "  - Text summary: go tool cover -func=coverage.out"
	@echo "  - HTML report: open coverage.html"

coverage-check:
	@go test -coverprofile=coverage.out ./... > /dev/null
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Total coverage: $$COVERAGE%"; \
	if [ "$$(echo "$$COVERAGE < 70" | bc -l)" ]; then \
		echo "❌ Coverage below 70% threshold"; \
		exit 1; \
	else \
		echo "✅ Coverage meets 70% threshold"; \
	fi
