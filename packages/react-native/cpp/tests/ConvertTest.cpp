// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "../Convert.h"
#include "TestMain.h"

using namespace derec;
using derec::testing::expect;

static void allocRoundTrip() {
  OwnedBytes b = allocBytes(4);
  expect(b.ptr != nullptr, "allocBytes returns non-null");
  expect(b.len == 4, "allocBytes honours the requested length");
  b.ptr[0] = 0xAB;
  expect(b.ptr[0] == 0xAB, "allocated memory is writable");
  freeBytes(b.ptr, b.len);
}

static void zeroLengthAlloc() {
  OwnedBytes b = allocBytes(0);
  expect(b.len == 0, "zero-length alloc reports zero length");
  freeBytes(b.ptr, b.len);
}

static void errorNamesComeFromRust() {
  auto named = errorName(/*category=*/11, /*code=*/10);
  expect(named.first == "share_store", "category 11 maps to share_store");
  expect(named.second == "missing_shared_key", "code 10 maps to missing_shared_key");
}

static void unknownErrorNames() {
  auto named = errorName(9999, -1);
  expect(named.first == "unknown", "unknown category");
  expect(named.second == "unknown", "unknown code");
}

int main() {
  derec::testing::run("allocRoundTrip", allocRoundTrip);
  derec::testing::run("zeroLengthAlloc", zeroLengthAlloc);
  derec::testing::run("errorNamesComeFromRust", errorNamesComeFromRust);
  derec::testing::run("unknownErrorNames", unknownErrorNames);
  return derec::testing::summary();
}
