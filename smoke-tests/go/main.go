// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Command go-binding-smoke-test is a runnable consumer of the DeRec Go SDK
// (github.com/derecalliance/lib-derec/packages/go), imported exactly as an
// external application would — through the module's public packages only.
// It mirrors smoke-tests/rust/src/{main,primitives,protocol}.rs: run the
// primitive-level produce/extract/process surface, then the stateful
// DeRecProtocol orchestrator, printing a pass line per flow and exiting
// non-zero the moment any assertion fails.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("── Primitives smoke tests ──────────────────────────────────")
	runPrimitives()

	fmt.Println()
	fmt.Println("── Protocol smoke tests ────────────────────────────────────")
	runProtocol()
	runEveryContactModePairs()
	runUnsafeHTTP()
	runConfigSurface()

	fmt.Println()
	fmt.Println("All smoke tests passed.")
}

// must fails the process if err is non-nil, prefixing it with context so a
// failure identifies which SDK call produced it.
func must(err error, context string) {
	if err != nil {
		fail("%s: %v", context, err)
	}
}

// assertTrue fails the process if cond is false.
func assertTrue(cond bool, format string, args ...any) {
	if !cond {
		fail(format, args...)
	}
}

// fail prints a diagnostic to stderr and exits the process with a non-zero
// status, so a broken invariant anywhere in the smoke test is observable to
// the caller (e.g. CI) rather than silently swallowed.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
