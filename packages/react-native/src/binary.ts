// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/**
 * The three FFI container formats.
 *
 * Most values cross this boundary as protobuf or JSON. Three do not: the C ABI
 * ferries a set of items as a single hand-packed little-endian buffer, because
 * a C signature cannot carry a variable-length array of variable-length items
 * without one. Each format is specified in the module header of the Rust file
 * that owns it, and the encoders below follow those specs exactly:
 *
 *   - the discovery secret list  (`library/src/interop/ffi/discovery.rs`)
 *   - the recovery response set  (`library/src/interop/ffi/recovery.rs`)
 *   - the committed-share map    (`library/src/interop/ffi/sharing.rs`)
 *
 * Everything here is representation, not protocol: no field is defaulted,
 * reordered or interpreted.
 */

import { utf8Decode, utf8Encode } from './codec';
import type { SecretVersionEntry, VersionEntry } from './types';

class Writer {
  private readonly chunks: Uint8Array[] = [];

  u32(value: number): void {
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, value, true);
    this.chunks.push(buffer);
  }

  u64(value: bigint): void {
    const buffer = new Uint8Array(8);
    new DataView(buffer.buffer).setBigUint64(0, value, true);
    this.chunks.push(buffer);
  }

  bytes(value: Uint8Array): void {
    this.chunks.push(value);
  }

  finish(): Uint8Array {
    let length = 0;
    for (const chunk of this.chunks) {
      length += chunk.length;
    }
    const out = new Uint8Array(length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

class Reader {
  private offset = 0;
  private readonly view: DataView;

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  private require(count: number): void {
    if (this.offset + count > this.data.length) {
      // A truncated container means the SDK and the library disagree about
      // the format. Failing loudly beats returning a half-read set that a
      // caller would take for the whole thing.
      throw new Error(
        `DeRec: malformed FFI container — wanted ${count} bytes at offset ${this.offset}, have ${
          this.data.length - this.offset
        }`,
      );
    }
  }

  u32(): number {
    this.require(4);
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  u64(): bigint {
    this.require(8);
    const value = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return value;
  }

  bytes(count: number): Uint8Array {
    this.require(count);
    const value = this.data.subarray(this.offset, this.offset + count);
    this.offset += count;
    return value;
  }

  atEnd(): boolean {
    return this.offset === this.data.length;
  }
}

function asBytes(buffer: Uint8Array | ArrayBuffer): Uint8Array {
  return buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
}

/** Discovery secret list — see `library/src/interop/ffi/discovery.rs`. */
export function encodeSecretList(entries: SecretVersionEntry[]): Uint8Array {
  const writer = new Writer();
  writer.u32(entries.length);
  for (const entry of entries) {
    writer.u64(entry.secret_id);
    writer.u32(entry.versions.length);
    for (const version of entry.versions) {
      writer.u32(version.version);
      const description = utf8Encode(version.description);
      writer.u32(description.length);
      writer.bytes(description);
    }
  }
  return writer.finish();
}

export function decodeSecretList(buffer: Uint8Array | ArrayBuffer): SecretVersionEntry[] {
  const reader = new Reader(asBytes(buffer));
  const count = reader.u32();
  const entries: SecretVersionEntry[] = [];
  for (let i = 0; i < count; i++) {
    const secretId = reader.u64();
    const versionCount = reader.u32();
    const versions: VersionEntry[] = [];
    for (let v = 0; v < versionCount; v++) {
      const version = reader.u32();
      const descriptionLength = reader.u32();
      versions.push({
        version,
        description: utf8Decode(reader.bytes(descriptionLength)),
      });
    }
    entries.push({ secret_id: secretId, versions });
  }
  return entries;
}

/**
 * Recovery response set — see `library/src/interop/ffi/recovery.rs`. Each
 * entry is a serialized `GetShareResponseMessage`, which the caller obtained
 * from `extract_get_share_response`.
 */
export function encodeShareResponses(responses: Uint8Array[]): Uint8Array {
  const writer = new Writer();
  writer.u32(responses.length);
  for (const response of responses) {
    writer.u32(response.length);
    writer.bytes(response);
  }
  return writer.finish();
}

/**
 * Committed-share map — see `library/src/interop/ffi/sharing.rs`. Entries
 * arrive sorted by channel id; the `Map` preserves that insertion order, so
 * iterating the result is deterministic.
 */
export function decodeCommittedShareEntries(
  buffer: Uint8Array | ArrayBuffer,
): Array<{ channelId: bigint; shareProto: Uint8Array }> {
  const reader = new Reader(asBytes(buffer));
  const count = reader.u32();
  const entries: Array<{ channelId: bigint; shareProto: Uint8Array }> = [];
  for (let i = 0; i < count; i++) {
    const channelId = reader.u64();
    const shareLength = reader.u32();
    entries.push({ channelId, shareProto: reader.bytes(shareLength) });
  }
  if (!reader.atEnd()) {
    throw new Error('DeRec: trailing bytes after the committed-share map');
  }
  return entries;
}
