// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Entry point for the dotnet bindings smoke test. Delegates to
// `Primitives.RunAll()` (low-level produce/extract/process surface)
// and `Protocol.RunAll()` (stateful DeRecProtocol orchestrator).
// Mirrors the `index.ts` / `main.ts` entry point pattern used by the
// nodejs and web bindings.

using System;
using DeRec.Bindings.Smoke;

internal static class Program
{
    private static void Main()
    {
        Primitives.RunAll();
        Protocol.RunAll();

        Console.WriteLine("All smoke tests passed.");
    }
}
