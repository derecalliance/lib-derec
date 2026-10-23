// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

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

namespace {

/// The `number-to-name` variants of `section` in the shared enum fixture, as
/// `(wire, text)` pairs.
std::vector<std::pair<int32_t, std::string>> fixtureNames(const std::string& section) {
  std::string path = std::string(__FILE__);
  path = path.substr(0, path.rfind('/')) + "/../../../../library/tests/fixtures/enums.json";
  std::ifstream file(path);
  std::stringstream text;
  text << file.rdbuf();
  std::string json = text.str();
  size_t start = json.find("\"" + section + "\": {");
  size_t end = start == std::string::npos ? start : json.find(']', start);
  std::vector<std::pair<int32_t, std::string>> out;
  if (start == std::string::npos || end == std::string::npos) {
    return out;
  }
  std::string body = json.substr(start, end - start);
  std::regex variant(R"re("wire":\s*(-?\d+),\s*"text":\s*"([^"]*)")re");
  for (std::sregex_iterator it(body.begin(), body.end(), variant), done; it != done; ++it) {
    out.emplace_back(std::stoi((*it)[1].str()), (*it)[2].str());
  }
  return out;
}

}  // namespace

static void errorNamesMatchTheEnumFixture() {
  auto categories = fixtureNames("DeRecErrorCategory");
  auto codes = fixtureNames("DeRecErrorCode");
  expect(!categories.empty(), "the fixture lists DeRecErrorCategory variants");
  expect(!codes.empty(), "the fixture lists DeRecErrorCode variants");
  for (const auto& [wire, text] : categories) {
    auto named = errorName(wire, 0);
    expect(named.first == text, "category " + std::to_string(wire) + " maps to " + text +
                                    ", got " + named.first);
  }
  for (const auto& [wire, text] : codes) {
    auto named = errorName(0, wire);
    expect(named.second == text,
           "code " + std::to_string(wire) + " maps to " + text + ", got " + named.second);
  }
}

int main() {
  derec::testing::run("allocRoundTrip", allocRoundTrip);
  derec::testing::run("zeroLengthAlloc", zeroLengthAlloc);
  derec::testing::run("errorNamesComeFromRust", errorNamesComeFromRust);
  derec::testing::run("unknownErrorNames", unknownErrorNames);
  derec::testing::run("errorNamesMatchTheEnumFixture", errorNamesMatchTheEnumFixture);
  return derec::testing::summary();
}
