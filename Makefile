APP=nullfinder

build:
	mkdir -p bin
	go build -o bin/$(APP) ./cmd/nullfinder

test:
	go test ./...

vet:
	go vet ./...

build-linux-amd64:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/$(APP)-linux-amd64 ./cmd/nullfinder

build-linux-arm64:
	mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/$(APP)-linux-arm64 ./cmd/nullfinder

build-darwin-amd64:
	mkdir -p dist
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o dist/$(APP)-darwin-amd64 ./cmd/nullfinder

build-darwin-arm64:
	mkdir -p dist
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o dist/$(APP)-darwin-arm64 ./cmd/nullfinder

release: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64
