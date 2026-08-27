.DEFAULT_GOAL := all

# `all` is the only public target, and it is all-or-nothing.
#
# Per-package targets used to exist (`make nodejs`, `make go`, ...). They are
# gone deliberately: every release problem this repository has hit came from a
# step that was available to skip — a package built without its tests, a
# manifest staged but not published, a version bumped in one place. A build
# that can be run partially will eventually be run partially.
#
# So this runs everything, in order, and stops at the first failure. If it
# exits zero, every package is built, every test has passed, and every staged
# artifact reports the same version. That is the only signal needed before
# publishing.
#
# Internal targets are prefixed `_` to keep them out of the tab-completion a
# developer sees; nothing outside this file should depend on them.

.PHONY: all _preflight _lint _test-rust _build _packages _test-native _test-js \
        _smoke _verify-versions

ROOT := ..
VERSION := $(shell $(ROOT)/scripts/get-version.sh)

define section
	@printf '\n\033[1m── %s\033[0m\n' $(1)
endef

all: _preflight _lint _test-rust _build _packages _test-native _test-js _smoke _verify-versions
	$(call section,"Release build complete")
	@printf 'Every package built and verified at version %s.\n' '$(VERSION)'
	@printf 'Staged for publication:\n'
	@printf '  crates      protobufs, cryptography, library (publish from source)\n'
	@printf '  npm         library/target/pkg-{nodejs,web,react-native}\n'
	@printf '  nuget       packages/dotnet/DeRec.Library/bin/Release/DeRec.Library.%s.nupkg\n' '$(VERSION)'
	@printf '  go          tag packages/go/v%s\n' '$(VERSION)'

# Fail early and by name rather than partway through with a cryptic error from
# whichever tool happens to be missing.
_preflight:
	$(call section,"Preflight")
	@for tool in cargo rustup wasm-pack cbindgen cargo-ndk dotnet go node npx rsync lipo xcodebuild; do \
	  command -v $$tool >/dev/null 2>&1 || { echo "missing required tool: $$tool" >&2; exit 1; }; \
	done
	@test -n "$$ANDROID_NDK_HOME" || { echo "ANDROID_NDK_HOME is not set" >&2; exit 1; }
	@test -d "$$ANDROID_NDK_HOME" || { echo "ANDROID_NDK_HOME does not exist: $$ANDROID_NDK_HOME" >&2; exit 1; }
	@test -n '$(VERSION)' || { echo "scripts/get-version.sh produced no version" >&2; exit 1; }
	@echo "tools present; building version $(VERSION)"

_lint:
	$(call section,"Lint")
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p derec-library --target wasm32-unknown-unknown -- -D warnings

_test-rust:
	$(call section,"Rust tests")
	cargo test --workspace
	cargo test -p derec-library --features ffi

_build:
	$(call section,"Native build")
	cargo build --release

_packages: _build
	$(call section,"Packaging: nodejs")
	wasm-pack build --release --out-dir target/pkg-nodejs --target nodejs
	node $(ROOT)/scripts/prepare-nodejs-package.mjs
	$(call section,"Packaging: web")
	wasm-pack build --release --out-dir target/pkg-web --target web
	node $(ROOT)/scripts/prepare-web-package.mjs
	$(call section,"Packaging: dotnet")
	$(ROOT)/scripts/prepare-dotnet-package.sh
	$(call section,"Packaging: go")
	$(ROOT)/scripts/prepare-go-package.sh
	$(call section,"Packaging: react-native")
	$(ROOT)/scripts/prepare-react-native-package.sh

# Tests that need the built artifacts: Go loads the freshly staged shared
# library, and the C++ harness links the release staticlib.
_test-native: _packages
	$(call section,"Go tests")
	# `-count=1` disables the test cache. The wire-golden test reads
	# library/tests/fixtures/wire_golden.json via os.ReadFile at run time, a
	# file Go's build graph does not see, so a cached run can report a stale
	# pass after the fixture changes underneath it.
	cd $(ROOT)/packages/go && CGO_ENABLED=0 go test -count=1 ./...
	$(call section,"C++ tests")
	$(ROOT)/packages/react-native/cpp/tests/run_tests.sh
	$(call section,".NET binding smoke")
	cd $(ROOT)/smoke-tests/dotnet && dotnet run --configuration Release
	$(call section,"Node.js binding smoke")
	cd $(ROOT)/smoke-tests/nodejs && ./run_test.sh

_test-js: _packages
	$(call section,"TypeScript tests")
	cd $(ROOT)/packages/react-native && npx tsc --noEmit && npx jest

# The one suite that needs hardware. It is part of `all` on purpose: a release
# that has not run against a real JSI runtime has not been tested, and every
# defect the React Native binding shipped with was invisible to every other
# suite here.
_smoke: _test-native _test-js
	$(call section,"On-device smoke tests")
	$(ROOT)/smoke-tests/react-native/run_test.sh

# The last thing standing between a green build and a wrong publish: every
# staged artifact must report the version `get-version.sh` resolved.
_verify-versions: _packages
	$(call section,"Version consistency")
	@$(ROOT)/scripts/verify-versions.sh
