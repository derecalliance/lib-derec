// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

namespace DeRec.Library;

/// <summary>
/// A protocol message timestamp in UTC, as carried on the wire: whole seconds
/// since the Unix epoch plus a non-negative nanosecond fraction.
/// </summary>
public sealed record Timestamp(long Seconds, int Nanos);
