.DEFAULT_GOAL := all

.PHONY: all native nodejs web web-dev nodejs-dev dotnet go

all: native nodejs web dotnet go

native:
	cargo build --release

nodejs: native
	wasm-pack build --release --out-dir target/pkg-nodejs --target nodejs
	node ../scripts/prepare-nodejs-package.mjs

web: native
	wasm-pack build --release --out-dir target/pkg-web --target web
	node ../scripts/prepare-web-package.mjs

# Development-only builds carrying the `unsafe-http` feature, which lets
# `TransportProtocol::validate` accept plaintext `http://` endpoints.
#
# Without it a local setup has no way to satisfy the `https://` requirement on
# the own-transport URI short of terminating TLS, and the refusal surfaces as an
# `INVALID_OWN_TRANSPORT` thrown at protocol construction — with nothing to
# suggest a Cargo feature is the cause.
#
# These overwrite the same output directories as `nodejs` / `web`, so re-run the
# plain target before packaging or publishing. Never ship a package built this
# way: enabling the feature also lets a peer-supplied `replyTo` downgrade the
# reply path to plaintext.
web-dev: native
	wasm-pack build --release --out-dir target/pkg-web --target web -- --features unsafe-http
	node ../scripts/prepare-web-package.mjs

nodejs-dev: native
	wasm-pack build --release --out-dir target/pkg-nodejs --target nodejs -- --features unsafe-http
	node ../scripts/prepare-nodejs-package.mjs

dotnet: native
	../scripts/prepare-dotnet-package.sh

go: native
	../scripts/prepare-go-package.sh
	cd ../packages/go && CGO_ENABLED=0 go test ./...
