.PHONY: build

all: build


deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure -vendor-only

.pre-build:
	mkdir -p build/darwin
	mkdir -p build/linux

build: .pre-build
	GOOS=darwin go build -i -o build/darwin/effigy.ext
	GOOS=linux CGO_ENABLED=0 go build -i -o build/linux/effigy.ext

run:
	./build/darwin/effigy.ext -socket /Users/$(shell whoami)/.osquery/shell.em

