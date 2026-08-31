// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Entry point for the Node.js smoke test suite.
// Runs the primitives tests first (low-level message functions), then the
// protocol tests (higher-level DeRecProtocol orchestrator).

import { runPrimitivesSmoke } from "./primitives.js";
import { runProtocolSmoke } from "./protocol.js";

console.log("╔══════════════════════════════════════════╗");
console.log("║  DeRec Node.js Smoke Tests               ║");
console.log("╚══════════════════════════════════════════╝\n");

runPrimitivesSmoke();

await runProtocolSmoke();

console.log("╔══════════════════════════════════════════╗");
console.log("║  All Node.js smoke tests passed. ✓       ║");
console.log("╚══════════════════════════════════════════╝");
