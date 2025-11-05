.PHONY: build build-main build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 clean

build: build-main

build-main:
	go build -o eip-toolkit eip_toolkit.go

# Cross-platform builds
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o eip-toolkit-linux-amd64 eip_toolkit.go

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o eip-toolkit-linux-arm64 eip_toolkit.go

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -o eip-toolkit-darwin-amd64 eip_toolkit.go

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o eip-toolkit-darwin-arm64 eip_toolkit.go

clean:
	rm -f eip-toolkit eip-toolkit-*

test:
	go test ./...

mod:
	go mod tidy

