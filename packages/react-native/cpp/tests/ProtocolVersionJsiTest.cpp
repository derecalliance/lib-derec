// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.

#include <hermes/hermes.h>

#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

/// The host `version` function hands JavaScript the core's protocol version
/// as two integers, exactly as `derec_protocol_version` reports it.
static void versionIsTheCoresMajorMinor() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  jsi::Value result =
      host.getPropertyAsFunction(*rt, "version").call(*rt);
  expect(result.isObject(), "version() returns an object");
  if (!result.isObject()) {
    return;
  }
  jsi::Object obj = result.asObject(*rt);
  jsi::Value major = obj.getProperty(*rt, "major");
  jsi::Value minor = obj.getProperty(*rt, "minor");
  expect(major.isNumber() && minor.isNumber(), "major and minor are numbers");
  if (!major.isNumber() || !minor.isNumber()) {
    return;
  }

  DeRecProtocolVersion core = derec_protocol_version();
  expect(major.asNumber() == static_cast<double>(core.major), "major matches the core");
  expect(minor.asNumber() == static_cast<double>(core.minor), "minor matches the core");
}

int main() {
  derec::testing::run("versionIsTheCoresMajorMinor", versionIsTheCoresMajorMinor);
  return derec::testing::summary();
}
