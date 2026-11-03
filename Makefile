VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test fmt-check vet demo cbom clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/pqledger ./cmd/pqledger

test:
	go test -race -cover ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)

vet:
	go vet ./...

# Scan the bundled examples plus a freshly generated Fabric-like crypto tree.
demo: build
	./scripts/gen-demo.sh
	./bin/pqledger scan examples

# Produce a CycloneDX CBOM and validate it against the official 1.6 schema.
cbom: build
	./scripts/gen-demo.sh
	./bin/pqledger scan examples -f cbom -o cbom.json
	python3 scripts/validate_cbom.py cbom.json

clean:
	rm -rf bin dist cbom.json examples/_generated
