// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//go:build darwin

package native

// libcPath is the libc image on darwin that exports malloc/free. libSystem
// is linked into every process, so this path is stable across macOS
// versions without depending on the derec dylib's own dependency list.
const libcPath = "/usr/lib/libSystem.B.dylib"
