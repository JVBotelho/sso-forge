.PHONY: build release clean test lint

BINARY := sso-forge
GO := go

build:
	$(GO) build -ldflags="-s -w" -o $(BINARY) .

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

release: clean
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-linux-amd64   .
	GOOS=linux   GOARCH=arm64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-linux-arm64   .
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-windows-amd64.exe .
	GOOS=darwin  GOARCH=amd64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-darwin-amd64  .
	GOOS=darwin  GOARCH=arm64 $(GO) build -ldflags="-s -w" -o dist/$(BINARY)-darwin-arm64  .

clean:
	rm -rf $(BINARY) dist/
