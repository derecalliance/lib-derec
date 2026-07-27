// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ebitengine/purego"
)

var (
	loadOnce  sync.Once
	libHandle uintptr
	loadErr   error
)

// load extracts the embedded native library to a stable per-version path
// under os.UserCacheDir() and Dlopens it. The path is content-addressed by a
// hash of the bytes so a new SDK version never collides with an old file. The
// file is written unconditionally on every load (write-to-temp then rename
// into place) rather than trusting a pre-existing file at that path, since
// the cache directory may be writable by other local users or processes.
func load() (uintptr, error) {
	loadOnce.Do(func() {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			loadErr = fmt.Errorf("derec: locate user cache dir: %w", err)
			return
		}
		sum := sha256.Sum256(libraryBytes)
		dir := filepath.Join(cacheDir, "derec-lib", hex.EncodeToString(sum[:]))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			loadErr = fmt.Errorf("derec: create lib cache dir: %w", err)
			return
		}
		path := filepath.Join(dir, libraryFileName)
		tmp, err := os.CreateTemp(dir, libraryFileName+".tmp-*")
		if err != nil {
			loadErr = fmt.Errorf("derec: create temp file for native lib: %w", err)
			return
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(libraryBytes); err != nil {
			tmp.Close()
			loadErr = fmt.Errorf("derec: write native lib: %w", err)
			return
		}
		if err := tmp.Close(); err != nil {
			loadErr = fmt.Errorf("derec: write native lib: %w", err)
			return
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			loadErr = fmt.Errorf("derec: install native lib: %w", err)
			return
		}
		h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			loadErr = fmt.Errorf("derec: dlopen native lib: %w", err)
			return
		}
		libHandle = h
	})
	return libHandle, loadErr
}

// symbol resolves a derec_* export address, panicking on any load/lookup
// failure — a missing symbol is an unrecoverable packaging bug, not a runtime
// condition callers can handle.
func symbol(name string) uintptr {
	h, err := load()
	if err != nil {
		panic(err)
	}
	addr, err := purego.Dlsym(h, name)
	if err != nil {
		panic(fmt.Errorf("derec: resolve symbol %q: %w", name, err))
	}
	return addr
}
