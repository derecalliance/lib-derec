.DEFAULT_GOAL := all

.PHONY: all native nodejs web dotnet go

all: native nodejs web dotnet go

native:
	cargo build --release

nodejs: native
	wasm-pack build --release --out-dir target/pkg-nodejs --target nodejs
	node ../scripts/prepare-nodejs-package.mjs

web: native
	wasm-pack build --release --out-dir target/pkg-web --target web
	node ../scripts/prepare-web-package.mjs

dotnet: native
	../scripts/prepare-dotnet-package.sh

go: native
	../scripts/prepare-go-package.sh
	cd ../packages/go && CGO_ENABLED=0 go test ./...
