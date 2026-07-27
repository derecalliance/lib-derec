// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//go:build linux && amd64

package native

import _ "embed"

//go:embed lib/linux_amd64/libderec_library.so
var libraryBytes []byte

const libraryFileName = "libderec_library.so"
