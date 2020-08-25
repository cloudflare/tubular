VERSION := $(shell git describe --tags --always --dirty="-dev")
ARCH    ?= amd64
GO      ?= go

export GOPROXY ?= off
export GOFLAGS ?= -mod=vendor -ldflags=-X=main.Version=$(VERSION)
export CLANG   ?= clang-9
export MAKEDIR  = $(CURDIR)

.SUFFIXES:
MAKEFLAGS+=-r

generated := internal/dispatcher_bpfel.go internal/dispatcher_bpfeb.go
deps := $(addsuffix .d,$(generated))

.PHONY: all
all: $(generated) $(deps)
	@mkdir -p "bin/$(ARCH)"
	GOARCH="$(ARCH)" $(GO) build -v -o "bin/$(ARCH)" ./cmd/...

internal/%_bpfel.go internal/%_bpfeb.go internal/%.go.d:
	$(GO) generate ./internal

.PHONY: package
package: tubular_$(VERSION)_$(ARCH).deb

tubular_$(VERSION)_%.deb: clean all
	mkdir -p deb/$*/usr/local/bin
	cp -f bin/$*/* deb/$*/usr/local/bin
	fpm --name tubular --version $(VERSION) --architecture $* \
		--chdir deb/$* --input-type dir --output-type deb .

.PHONY: test
test:
	$(GO) test -race -short -v ./...

.PHONY: lint
lint:
	test -z $$(gofmt -l $$(find . -name '*.go' ! -path './vendor/*'))

.PHONY: clean
clean:
	$(RM) -r bin deb *.deb $(deps)

ifneq ($(MAKECMDGOALS),clean)
-include $(deps)
endif
