// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//go:build darwin && amd64

package native

import _ "embed"

//go:embed lib/darwin_amd64/libderec_library.dylib
var libraryBytes []byte

const libraryFileName = "libderec_library.dylib"
