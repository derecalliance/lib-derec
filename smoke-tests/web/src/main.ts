// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Entry point for the Web smoke test suite.
// Runs the primitives tests first (low-level message functions), then the
// protocol tests (higher-level DeRecProtocol orchestrator).

import { init } from "@derec-alliance/web";
import { runPrimitivesSmoke } from "./primitives";
import { runProtocolSmoke } from "./protocol";

async function main(): Promise<void> {
  await init();

  console.log("╔══════════════════════════════════════════╗");
  console.log("║  DeRec Web Smoke Tests                   ║");
  console.log("╚══════════════════════════════════════════╝\n");

  await runPrimitivesSmoke();

  await runProtocolSmoke();

  console.log("╔══════════════════════════════════════════╗");
  console.log("║  All web smoke tests passed. ✓           ║");
  console.log("╚══════════════════════════════════════════╝");

  const app = document.getElementById("app");
  if (app) {
    app.textContent =
      "DeRec web smoke tests completed. Check the browser console for results.";
  }
}

main().catch((error: unknown) => {
  console.error("Web smoke test failed:", error);
  const app = document.getElementById("app");
  if (app) {
    app.textContent = `DeRec web smoke test failed: ${String(error)}`;
  }
});
