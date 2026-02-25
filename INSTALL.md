# Protobuf (`protoc`)

Building this project requires the **Protocol Buffers compiler**: `protoc`.

Verify it's available:

```bash
protoc --version
```

If `protoc` is installed but not on your `PATH`, you can set:
```bash
export PROTOC=/path/to/protoc
```

## macOS

### Homebrew
```bash
brew install protobuf
protoc --version
```

## Linux

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler
protoc --version
```

### Fedora

```bash
sudo dnf install -y protobuf-compiler
protoc --version
```

## Windows

### Chocolatey

```ps
choco install protoc
protoc --version
```

### Scoop

```ps
scoop install protobuf
protoc --version
```

# WASM Targets

NodeJS/Web WASM targets require `wasm-pack`

```bash
cargo install wasm-pack
wasm-pack --version
```

# Typescript bindings

The typescript bindings require the bunx tool, which can be installed as follows.
```
curl -fsSL https://bun.sh/install | bash
bun --version
bunx --version
```
