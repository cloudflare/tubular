VERSION := $(shell git describe --tags --always --dirty="-dev")
ARCH    ?= amd64
GO      ?= go

export GOFLAGS ?= -mod=vendor -ldflags=-X=main.Version=$(VERSION)
export CLANG   ?= clang-9

.PHONY: all
all:
	@mkdir -p "bin/$(ARCH)"
	$(GO) generate ./...
	GOARCH="$(ARCH)" $(GO) build -v -o "bin/$(ARCH)" ./cmd/...

.PHONY: package
package: tubular_$(VERSION)_$(ARCH).deb

tubular_$(VERSION)_%.deb: all
	mkdir -p deb/$*/usr/local/bin
	cp -f bin/$*/* deb/$*/usr/local/bin
	fpm --name tubular --version $(VERSION) --architecture $* \
		--chdir deb/$* --input-type dir --output-type deb .

.PHONY: test
test:
	$(GO) test -race -short -v ./...

.PHONY: lint
lint:
	test -z $$(gofmt -l $$(find . -name *.go | grep -v './vendor'))

.PHONY: clean
clean:
	$(RM) -r bin deb *.deb
