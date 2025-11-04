.PHONY: build build-ultra-simple build-simple clean

build: build-ultra-simple build-simple

build-ultra-simple:
	go build -o eip-toolkit-ultra-simple eip_toolkit_ultra_simple.go

build-simple:
	go build -o eip-toolkit-simple eip_toolkit_simple.go

clean:
	rm -f eip-toolkit-ultra-simple eip-toolkit-simple

test:
	go test ./...

mod:
	go mod tidy

