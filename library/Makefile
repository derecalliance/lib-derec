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

.PHONY: all check-descriptor _preflight _lint _docs _test-rust _build _packages \
        _test-packaging _test-native _test-js _smoke _verify-versions

ROOT := ..
VERSION := $(shell $(ROOT)/scripts/get-version.sh)

define section
	@printf '\n\033[1m── %s\033[0m\n' $(1)
endef

all: _preflight _lint _docs _test-rust _build _packages _test-packaging _test-native _test-js _smoke check-descriptor _verify-versions
	$(call section,"Release build complete")
	@printf 'Every package built and verified at version %s.\n' '$(VERSION)'
	@printf 'Staged for publication:\n'
	@printf '  crates      protobufs, cryptography, library (publish from source)\n'
	@printf '  npm         library/target/pkg-{nodejs,web,react-native}\n'
	@printf '  nuget       packages/dotnet/DeRec.Library/bin/Release/DeRec.Library.%s.nupkg\n' '$(VERSION)'
	@printf '  go          tag packages/go/v%s\n' '$(VERSION)'

check-descriptor:
	../scripts/check-descriptor-optional.sh

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

# Three crates publish to docs.rs, so a broken intra-doc link is as public as
# a broken API. `-D warnings` makes rustdoc's lints fail the build the way
# clippy's already do.
#
# Three configurations, because a link can resolve under one and not another
# and each of these has caught something the others did not:
#
#   default          what `cargo doc` gives someone with this crate as a
#                    dependency. Strictest for links *into* gated items,
#                    since those items are absent here.
#   --features serde what docs.rs publishes, per `package.metadata.docs.rs`.
#                    `interop::dto` and `types::state_record` exist only with
#                    this feature, so their docs are unchecked without it.
#   wasm32           the WASM binding's own docs. Nothing else in this file
#                    reads them, and `cargo doc` never runs for that target
#                    incidentally.
#
# Scoped to `-p derec-library` for wasm32: the workspace also holds a host-only
# smoke-test binary that does not build for that target.
_docs:
	$(call section,"Documentation")
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
	RUSTDOCFLAGS="-D warnings" cargo doc -p derec-library --no-deps --features serde
	RUSTDOCFLAGS="-D warnings" cargo doc -p derec-library --no-deps \
	    --target wasm32-unknown-unknown

_test-rust:
	$(call section,"Rust tests")
	cargo test --workspace
	cargo test -p derec-library --features ffi
# `derec-proto`'s descriptor tests are gated behind a default-off feature, and
# the only crate that enables it does so as a build-dependency. The feature
# resolver keeps build-dependency features separate from normal ones, so
# `--workspace` compiles that test file to zero tests. It needs its own run.
	cargo test -p derec-proto --features descriptor

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

# Each packaging script embeds the schema bundle by hand; nothing forces a
# script that forgets to copy it to fail loudly on its own (the .NET csproj's
# wildcard `Include`, for one, silently expands to zero items). Runs after
# `_packages` so it inspects what was actually staged and packed, not what
# was meant to be.
_test-packaging: _packages
	$(call section,"Packaging: schema bundle assertions")
	$(ROOT)/scripts/test-schema-bundle.sh
	$(ROOT)/scripts/test-go-schema-freshness.sh
	$(ROOT)/scripts/test-npm-schema-packaging.sh
	$(ROOT)/scripts/test-dotnet-schema-packaging.sh
	$(ROOT)/scripts/test-react-native-schema-packaging.sh

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
# staged artifact, and every version the crates pin each other by, must report
# the version `get-version.sh` resolved. Runs after `_packages` so it reads
# what was actually built rather than what was meant to be.
#
# The Go module tag is the sole exception. Go has no manifest to inspect, and
# the tag is pushed after publishing, so it is reported as a warning rather
# than failing a build that is otherwise ready.
_verify-versions: _packages
	$(call section,"Version consistency")
	@$(ROOT)/scripts/verify-versions.sh
