// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <cstdio>
#include <string>

namespace derec::testing {

inline int& failures() {
  static int count = 0;
  return count;
}

inline int& checks() {
  static int count = 0;
  return count;
}

inline void expect(bool condition, const std::string& what) {
  ++checks();
  if (!condition) {
    ++failures();
    std::fprintf(stderr, "  FAIL: %s\n", what.c_str());
  }
}

inline void run(const char* name, void (*body)()) {
  std::fprintf(stderr, "- %s\n", name);
  body();
}

inline int summary() {
  std::fprintf(stderr, "\n%d checks, %d failures\n", checks(), failures());
  return failures() == 0 ? 0 : 1;
}

}  // namespace derec::testing
