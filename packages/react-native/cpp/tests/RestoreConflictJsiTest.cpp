#include <hermes/hermes.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../Convert.h"
#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

// Stores backing a real `derec_protocol_new` handle. Every load reports
// "not found", every listing is empty except `list_helpers`, which returns
// whatever the test placed in `helpersJson`, and every write succeeds.
std::string helpersJson = "[]";

int32_t giveBytes(const std::string& text, uint8_t** outPtr, size_t* outLen) {
  auto* ptr = static_cast<uint8_t*>(std::malloc(text.size()));
  std::memcpy(ptr, text.data(), text.size());
  *outPtr = ptr;
  *outLen = text.size();
  return 0;
}

void freeBytes(void*, uint8_t* ptr, size_t) { std::free(ptr); }

int32_t chLoad(void*, uint64_t, uint64_t, uint64_t, uint8_t**, size_t*) { return 1; }
int32_t chSave(void*, uint64_t, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t chRemove(void*, uint64_t, uint64_t, uint64_t, uint32_t* existed) {
  *existed = 0;
  return 0;
}
int32_t chListHelpers(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes(helpersJson, p, l);
}
int32_t chListReplicas(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t chLink(void*, uint64_t, uint64_t, uint64_t) { return 0; }
int32_t chLinked(void*, uint64_t, uint64_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}

int32_t seLoad(void*, uint64_t, uint64_t, uint32_t, uint8_t**, size_t*) { return 1; }
int32_t seLoadMany(void*, uint64_t, const uint8_t*, size_t, uint32_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t seSave(void*, uint64_t, uint64_t, uint32_t, const uint8_t*, size_t) { return 0; }
int32_t seRemove(void*, uint64_t, uint64_t, uint32_t) { return 0; }

int32_t shLoad(void*, uint64_t, uint64_t, const uint8_t*, size_t, uint8_t**, size_t*) {
  return 1;
}
int32_t shLoadMany(void*, uint64_t, const uint8_t*, size_t, const uint8_t*, size_t,
                   uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t shLoadAll(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t shLatest(void*, uint64_t, uint32_t* has, uint32_t* version) {
  *has = 0;
  *version = 0;
  return 0;
}
int32_t shSave(void*, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t shRemove(void*, uint64_t, uint64_t) { return 0; }
int32_t shRemoveVersions(void*, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }

int32_t usLoad(void*, uint64_t, uint8_t**, size_t*) { return 1; }
int32_t usSave(void*, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t usRemove(void*, uint64_t) { return 0; }

int32_t stSave(void*, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t stLoad(void*, uint64_t, const uint8_t*, size_t, uint8_t**, size_t*) { return 1; }
int32_t stRemove(void*, uint64_t, const uint8_t*, size_t, uint32_t* removed) {
  *removed = 0;
  return 0;
}
int32_t stLoadAll(void*, uint64_t, uint32_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}

int32_t trSend(void*, const uint8_t*, size_t, const uint8_t*, size_t) { return 0; }

ChannelStoreCallbacks channelStore{nullptr, chLoad, chSave, chRemove, chListHelpers,
                                   chListReplicas, chLink, chLinked, freeBytes};
SecretStoreCallbacks secretStore{nullptr, seLoad, seLoadMany, seSave, seRemove, freeBytes};
ShareStoreCallbacks shareStore{nullptr,  shLoad,   shLoadMany,       shLoadAll, shLatest,
                               shSave,   shRemove, shRemoveVersions, freeBytes};
UserSecretStoreCallbacks userSecretStore{nullptr, usLoad, usSave, usRemove, freeBytes};
StateStoreCallbacks stateStore{nullptr, stSave, stLoad, stRemove, stLoadAll, freeBytes};
TransportCallbacks transport{nullptr, trSend};

DeRecProtocolHandle* newProtocol() {
  std::string config =
      R"({"secret_id":"1","own_transports":[{"uri":"https://owner.example.com","protocol":0}]})";
  DeRecProtocolNewResult created = derec_protocol_new(
      reinterpret_cast<const uint8_t*>(config.data()), config.size(), nullptr, 0,
      &channelStore, &secretStore, &shareStore, &userSecretStore, &stateStore, &transport);
  if (created.error.code != 0) {
    std::fprintf(stderr, "  derec_protocol_new: %s\n",
                 created.error.message == nullptr ? "" : created.error.message);
    derec_free_error(&created.error);
  }
  return created.handle;
}

// Two helpers at canonical channel ids 11 and 22, as in
// `library/tests/fixtures/wire_golden.json`'s restore fixture (whose replica
// group is dropped: its 10-byte key would fail the invariant check first).
const std::string kRestoreParams =
    R"({"version":7,"recovered_secret":{"helpers":[)"
    R"({"channel_id":"11","transports":[{"uri":"https://helper-a.example.com","protocol":"https"}],)"
    R"("shared_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]},)"
    R"({"channel_id":"22","transports":[{"uri":"https://helper-b.example.com","protocol":"https"}],)"
    R"("shared_key":[31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0]}],)"
    R"("secrets":[{"id":[1],"name":"wallet","data":[1,2,3]}]}})";

std::string helperRow(const char* channelId) {
  return std::string(R"({"channel_id":)") + channelId +
         R"(,"transports":[{"uri":"https://stale.example.com","protocol":0}],"peer_role":"Helper"})";
}

// Drives the exact sequence `ProtocolHost`'s `restore` runs: the FFI call,
// `takeRestoreResult` on the worker, then `throwDeRecError` on the JS thread.
derec::RestoreOutcome runRestore() {
  DeRecProtocolHandle* handle = newProtocol();
  expect(handle != nullptr, "derec_protocol_new produced a handle");
  DeRecProtocolRestoreResult result = derec_protocol_restore(
      handle, reinterpret_cast<const uint8_t*>(kRestoreParams.data()), kRestoreParams.size());
  derec::RestoreOutcome outcome = derec::takeRestoreResult(result);
  derec_protocol_free(handle);
  return outcome;
}

}  // namespace

static void conflictCarriesChannelIds() {
  helpersJson = "[" + helperRow("11") + "," + helperRow("22") + "," + helperRow("99") + "]";
  derec::RestoreOutcome outcome = runRestore();
  expect(outcome.error.code == DEREC_CODE_RESTORE_CONFLICT,
         "restore over channels at canonical ids fails with restore_conflict (got " +
             std::to_string(outcome.error.code) + ": " +
             (outcome.error.message == nullptr ? "" : outcome.error.message) + ")");
  expect(outcome.events.empty(), "a failed restore carries no events");

  auto rt = facebook::hermes::makeHermesRuntime();
  jsi::Value thrown;
  try {
    derec::throwDeRecError(*rt, outcome.error, outcome.conflictingChannelIdsJson);
  } catch (const jsi::JSError& error) {
    thrown = jsi::Value(*rt, error.value());
  }
  expect(thrown.isObject(), "the rejection is a structured error object");
  if (!thrown.isObject()) {
    return;
  }
  auto object = thrown.asObject(*rt);
  expect(object.getProperty(*rt, "code").asString(*rt).utf8(*rt) == "restore_conflict",
         "code is restore_conflict");
  jsi::Value ids = object.getProperty(*rt, "channel_ids");
  expect(ids.isObject() && ids.asObject(*rt).isArray(*rt), "channel_ids is an array");
  if (!ids.isObject() || !ids.asObject(*rt).isArray(*rt)) {
    return;
  }
  auto array = ids.asObject(*rt).asArray(*rt);
  std::vector<std::string> got;
  for (size_t i = 0; i < array.size(*rt); ++i) {
    jsi::Value item = array.getValueAtIndex(*rt, i);
    expect(item.isString(), "every channel id is a string");
    if (item.isString()) {
      got.push_back(item.asString(*rt).utf8(*rt));
    }
  }
  expect(got == std::vector<std::string>({"11", "22"}),
         "channel_ids lists exactly the colliding ids, as decimal strings");
}

static void otherErrorsCarryNoChannelIds() {
  auto rt = facebook::hermes::makeHermesRuntime();
  DeRecError error{};
  error.code = DEREC_CODE_ALREADY_RESTORED;
  jsi::Value thrown;
  try {
    derec::throwDeRecError(*rt, error, {});
  } catch (const jsi::JSError& e) {
    thrown = jsi::Value(*rt, e.value());
  }
  expect(thrown.isObject() &&
             thrown.asObject(*rt).getProperty(*rt, "channel_ids").isUndefined(),
         "an error with no conflicting ids has no channel_ids property");
}

static void successStillReturnsEvents() {
  helpersJson = "[]";
  derec::RestoreOutcome outcome = runRestore();
  expect(outcome.error.code == DEREC_CODE_OK,
         "restore into an empty namespace succeeds (got " +
             std::to_string(outcome.error.code) + ": " +
             (outcome.error.message == nullptr ? "" : outcome.error.message) + ")");
  if (outcome.error.code != DEREC_CODE_OK) {
    derec_free_error(&outcome.error);
  }
  std::string events(outcome.events.begin(), outcome.events.end());
  expect(!events.empty() && events.front() == '[' && events.back() == ']',
         "a successful restore returns the events JSON array: " + events);
  expect(outcome.conflictingChannelIdsJson.empty(),
         "a successful restore reports no conflicting ids");
}

static void generateReplicaIdIsNonZeroBigInt() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);
  auto generate = host.getPropertyAsFunction(*rt, "generate_replica_id");
  jsi::Value first = generate.call(*rt);
  jsi::Value second = generate.call(*rt);
  expect(first.isBigInt() && second.isBigInt(), "generate_replica_id returns a bigint");
  if (!first.isBigInt() || !second.isBigInt()) {
    return;
  }
  uint64_t a = first.asBigInt(*rt).asUint64(*rt);
  uint64_t b = second.asBigInt(*rt).asUint64(*rt);
  expect(a != 0 && b != 0, "generated replica ids are never 0");
  expect(a != b, "two generated replica ids differ");
}

int main() {
  derec::testing::run("conflictCarriesChannelIds", conflictCarriesChannelIds);
  derec::testing::run("otherErrorsCarryNoChannelIds", otherErrorsCarryNoChannelIds);
  derec::testing::run("successStillReturnsEvents", successStillReturnsEvents);
  derec::testing::run("generateReplicaIdIsNonZeroBigInt", generateReplicaIdIsNonZeroBigInt);
  return derec::testing::summary();
}
