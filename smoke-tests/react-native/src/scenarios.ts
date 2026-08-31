// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Scenario registry for the on-device smoke test.
//
// `runPrimitives` and `runProtocol` are the ported Node.js suites; the
// teardown hazards below are React Native's own, covering the two lifetime
// risks no other SDK has — a native handle released while store callbacks are
// still outstanding, and a protocol instance whose worker thread must drain
// before the handle goes away.

import { DeRecProtocolBuilder } from "@derec-alliance/react-native";
import type {
  ChannelStore,
  SecretStore,
  ShareStore,
  StateStore,
  Transport,
  UserSecrets,
  UserSecretStore,
} from "@derec-alliance/react-native";

import { runPrimitivesSmoke } from "./primitives";
import { runProtocolSmoke } from "./protocol";

export function assertTrue(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

export function runPrimitives(): void {
  runPrimitivesSmoke();
}

export async function runProtocol(): Promise<void> {
  await runProtocolSmoke();
}

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A store whose every method takes `delayMs` to settle, so a protocol call can
 * be caught mid-callback. The values it returns are irrelevant — these
 * scenarios assert on lifetime, not on protocol outcomes.
 */
class SlowChannelStore implements ChannelStore {
  constructor(private readonly delayMs: number) {}

  async load(): Promise<Uint8Array | null> {
    await delay(this.delayMs);
    return null;
  }

  async save(): Promise<void> {
    await delay(this.delayMs);
  }

  async remove(): Promise<boolean> {
    await delay(this.delayMs);
    return false;
  }

  async listHelpers(): Promise<Uint8Array | null> {
    await delay(this.delayMs);
    return null;
  }

  async listReplicas(): Promise<Uint8Array | null> {
    await delay(this.delayMs);
    return null;
  }

  async linkChannel(): Promise<void> {
    await delay(this.delayMs);
  }

  async linkedChannels(): Promise<string[]> {
    await delay(this.delayMs);
    return [];
  }
}

class EmptySecretStore implements SecretStore {
  async load(): Promise<null> {
    return null;
  }
  async loadMany(_s: string, channelIds: string[]): Promise<Array<null>> {
    return channelIds.map(() => null);
  }
  async save(): Promise<void> {}
  async remove(): Promise<void> {}
}

class EmptyShareStore implements ShareStore {
  async load(): Promise<[]> {
    return [];
  }
  async loadMany(): Promise<[]> {
    return [];
  }
  async loadAll(): Promise<[]> {
    return [];
  }
  async save(): Promise<void> {}
  async latestVersion(): Promise<null> {
    return null;
  }
  async removeChannel(): Promise<void> {}
}

class EmptyUserSecretStore implements UserSecretStore {
  async loadLatest(): Promise<UserSecrets | null> {
    return null;
  }
  async saveLatest(): Promise<void> {}
  async remove(): Promise<void> {}
}

class EmptyStateStore implements StateStore {
  async save(): Promise<void> {}
  async load(): Promise<null> {
    return null;
  }
  async remove(): Promise<boolean> {
    return false;
  }
  async loadAll(): Promise<[]> {
    return [];
  }
}

class DiscardingTransport implements Transport {
  async send(): Promise<void> {}
}

function buildSlowProtocol(storeDelayMs: number) {
  return new DeRecProtocolBuilder(0xde_2ecn)
    .withChannelStore(new SlowChannelStore(storeDelayMs))
    .withShareStore(new EmptyShareStore())
    .withSecretStore(new EmptySecretStore())
    .withUserSecretStore(new EmptyUserSecretStore())
    .withStateStore(new EmptyStateStore())
    .withTransport(new DiscardingTransport())
    .withOwnTransport({ uri: "https://teardown.example", protocol: "https" })
    .build();
}

/**
 * Frees a protocol instance while store callbacks are still outstanding.
 *
 * The binding must drain its worker before releasing the handle, so this must
 * complete rather than hang or crash. A native `free` that raced the worker
 * would either use the handle after `derec_protocol_free` or abandon a thread
 * blocked in `JsCallbackBridge::callSync`; both show up here as a hang, which
 * the harness surfaces as a smoke-test timeout rather than a pass.
 */
export async function runTeardownHazards(): Promise<void> {
  const protocol = buildSlowProtocol(500);
  const inFlight = protocol.tick();
  protocol.free();
  await inFlight.catch(() => undefined);
  assertTrue(true, "freeing with calls in flight completed");

  // `free` is documented as safe to call more than once; a second call must
  // not fault on an already-released handle.
  const reFreed = buildSlowProtocol(0);
  reFreed.free();
  reFreed.free();
  assertTrue(true, "double free is a no-op");

  // Work posted after teardown must be rejected, not silently queued onto a
  // worker that will never run it.
  const afterFree = buildSlowProtocol(0);
  afterFree.free();
  let rejected = false;
  await afterFree.tick().then(
    () => undefined,
    () => {
      rejected = true;
    },
  );
  assertTrue(rejected, "a call issued after free must reject");
}
