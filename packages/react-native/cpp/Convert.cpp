// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "Convert.h"

#include <cstdlib>
#include <cstring>

namespace derec {

OwnedBytes allocBytes(size_t len) {
  if (len == 0) {
    return OwnedBytes{nullptr, 0};
  }
  auto* ptr = static_cast<uint8_t*>(std::malloc(len));
  return OwnedBytes{ptr, ptr == nullptr ? 0 : len};
}

void freeBytes(uint8_t* ptr, size_t /*len*/) {
  if (ptr != nullptr) {
    std::free(ptr);
  }
}

std::vector<uint8_t> takeBuffer(DeRecBuffer& buffer) {
  std::vector<uint8_t> out;
  if (buffer.ptr != nullptr && buffer.len > 0) {
    out.assign(buffer.ptr, buffer.ptr + buffer.len);
  }
  derec_free_buffer(buffer.ptr, buffer.len);
  buffer.ptr = nullptr;
  buffer.len = 0;
  return out;
}

std::string takeString(char* owned) {
  if (owned == nullptr) {
    return {};
  }
  std::string out(owned);
  derec_free_string(owned);
  return out;
}

std::pair<std::string, std::string> errorName(int32_t category, int32_t code) {
  return {std::string(derec_error_category_name(category)),
          std::string(derec_error_code_name(code))};
}

}  // namespace derec
