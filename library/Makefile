.PHONY: all native node web

all: native node web

native:
	cargo b --release

node:
	wasm-pack build --out-dir target/pkg-node --target nodejs

web:
	wasm-pack build --out-dir target/pkg-web --target web
