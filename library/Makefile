.DEFAULT_GOAL := all

.PHONY: all native nodejs web dotnet go react-native

all: native nodejs web dotnet go react-native

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
	# `-count=1` disables the test cache. The wire-golden test reads
	# bindings/test_fixture/wire_golden.json via os.ReadFile at run time, a
	# file Go's build graph does not see, so a cached run can report a stale
	# pass after the fixture changes underneath it.
	cd ../packages/go && CGO_ENABLED=0 go test -count=1 ./...

react-native: native
	../scripts/prepare-react-native-package.sh
