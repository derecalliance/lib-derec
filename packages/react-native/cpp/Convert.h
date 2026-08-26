// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// A byte buffer allocated by this binding. Ownership passes to Rust across a
/// store callback out-parameter; Rust copies the contents and hands the
/// pointer back through the callback struct's `free_buffer`.
struct OwnedBytes {
  uint8_t* ptr;
  size_t len;
};

OwnedBytes allocBytes(size_t len);
void freeBytes(uint8_t* ptr, size_t len);

/// Copy `buffer` into a vector and release the Rust allocation.
std::vector<uint8_t> takeBuffer(DeRecBuffer& buffer);

/// Copy a Rust-owned C string and release it via `derec_free_string`.
std::string takeString(char* owned);

/// Resolve the `(category, code)` name pair from the crate's accessors.
std::pair<std::string, std::string> errorName(int32_t category, int32_t code);

}  // namespace derec
