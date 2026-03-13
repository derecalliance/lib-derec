.DEFAULT_GOAL := all

.PHONY: all native nodejs web dotnet

all: native nodejs web dotnet

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
