.PHONY: all native node web

all: native node web

native:
	cargo b --release

nodejs:
	wasm-pack build --release --out-dir target/pkg-nodejs --target nodejs
	node ../scripts/prepare-nodejs-package.mjs

web:
	wasm-pack build --release  --out-dir target/pkg-web --target web
	node ../scripts/prepare-web-package.mjs
