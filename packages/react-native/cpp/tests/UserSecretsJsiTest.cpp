// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.

#include <hermes/hermes.h>

#include <string>
#include <vector>

#include "../UserSecretsJson.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

std::unique_ptr<jsi::Runtime> makeRuntime() { return facebook::hermes::makeHermesRuntime(); }

std::vector<uint8_t> bytesOf(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string textOf(const std::vector<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

/// Rust's `saveLatest` payload -> the JS object the store receives -> what
/// the store hands back on `loadLatest`, as Rust reads it.
std::string roundTrip(const std::string& wire) {
  auto rt = makeRuntime();
  auto bytes = bytesOf(wire);
  jsi::Value js = derec::userSecretsFromWire(*rt, bytes.data(), bytes.size());
  return textOf(derec::userSecretsToWire(*rt, js.asObject(*rt)));
}

}  // namespace

static void authorReplicaIdRoundTrips() {
  const std::string wire =
      "{\"version\":4,\"secrets\":[{\"id\":[1,2],\"name\":\"n\",\"data\":[255,0]}],"
      "\"description\":\"d\",\"author_replica_id\":\"18446744073709551615\"}";
  std::string back = roundTrip(wire);
  expect(back.find("\"author_replica_id\":\"18446744073709551615\"") != std::string::npos,
         "author_replica_id survives save -> load verbatim: " + back);
  expect(back.find("\"description\":\"d\"") != std::string::npos, "description survives");
  expect(back.find("\"version\":4") != std::string::npos, "version survives");
  expect(back.find("\"id\":[1,2]") != std::string::npos, "secret id bytes survive");
  expect(back.find("\"data\":[255,0]") != std::string::npos, "secret data bytes survive");
}

static void storeSeesAuthorReplicaIdAsString() {
  auto rt = makeRuntime();
  auto bytes = bytesOf(
      "{\"version\":1,\"secrets\":[],\"author_replica_id\":\"42\"}");
  jsi::Object js = derec::userSecretsFromWire(*rt, bytes.data(), bytes.size()).asObject(*rt);
  jsi::Value author = js.getProperty(*rt, "author_replica_id");
  expect(author.isString() && author.asString(*rt).utf8(*rt) == "42",
         "the JS store receives author_replica_id as the decimal string");
}

static void absentAuthorStaysAbsent() {
  std::string back = roundTrip("{\"version\":1,\"secrets\":[]}");
  expect(back.find("author_replica_id") == std::string::npos,
         "no author_replica_id is invented: " + back);
  expect(back.find("description") == std::string::npos, "no description is invented: " + back);
}

int main() {
  derec::testing::run("authorReplicaIdRoundTrips", authorReplicaIdRoundTrips);
  derec::testing::run("storeSeesAuthorReplicaIdAsString", storeSeesAuthorReplicaIdAsString);
  derec::testing::run("absentAuthorStaysAbsent", absentAuthorStaysAbsent);
  return derec::testing::summary();
}
