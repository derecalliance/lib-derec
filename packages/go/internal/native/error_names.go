// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

var (
	errorCategoryNameOnce sync.Once
	errorCategoryNameFn   func(category int32) *byte

	errorCodeNameOnce sync.Once
	errorCodeNameFn   func(code int32) *byte
)

// ErrorCategoryName returns the library's name for a DEREC_CATEGORY_* value
// ("unknown" for unrecognized values). The C string is static and is copied,
// never freed.
func ErrorCategoryName(category int32) string {
	errorCategoryNameOnce.Do(func() {
		purego.RegisterFunc(&errorCategoryNameFn, symbol("derec_error_category_name"))
	})
	return cString(errorCategoryNameFn(category))
}

// ErrorCodeName returns the library's name for a DEREC_CODE_* value
// ("unknown" for unrecognized values). The C string is static and is copied,
// never freed.
func ErrorCodeName(code int32) string {
	errorCodeNameOnce.Do(func() {
		purego.RegisterFunc(&errorCodeNameFn, symbol("derec_error_code_name"))
	})
	return cString(errorCodeNameFn(code))
}
