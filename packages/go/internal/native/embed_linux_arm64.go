// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//go:build linux && arm64

package native

import _ "embed"

//go:embed lib/linux_arm64/libderec_library.so
var libraryBytes []byte

const libraryFileName = "libderec_library.so"
