.PHONY: build build-ultra-simple build-simple build-main clean

build: build-ultra-simple build-simple build-main

build-ultra-simple:
	go build -o eip-toolkit-ultra-simple eip_toolkit_ultra_simple.go

build-simple:
	go build -o eip-toolkit-simple eip_toolkit_simple.go

build-main:
	go build -o eip-toolkit eip_toolkit.go

clean:
	rm -f eip-toolkit-ultra-simple eip-toolkit-simple eip-toolkit

test:
	go test ./...

mod:
	go mod tidy

