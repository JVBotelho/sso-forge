.PHONY: build release clean test lint sbom verify

BINARY := sso-forge
GO := go

build:
	$(GO) build -ldflags="-s -w" -o $(BINARY) .

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

sbom:
	@command -v syft >/dev/null 2>&1 || { echo "syft not found: install via https://github.com/anchore/syft"; exit 1; }
	syft . -o spdx-json > dist/sbom.spdx.json

release: clean
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-linux-amd64   .
	GOOS=linux   GOARCH=arm64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-linux-arm64   .
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-windows-amd64.exe .
	GOOS=darwin  GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-darwin-amd64  .
	GOOS=darwin  GOARCH=arm64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-darwin-arm64  .
	cd dist && sha256sum $(BINARY)-* > checksums.txt

verify:
	$(GO) mod verify

clean:
	rm -rf $(BINARY) dist/
