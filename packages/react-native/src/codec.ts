// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// ---------------------------------------------------------------------------
// UTF-8 byte <-> string codec, shared by every JSON payload that crosses the
// JSI boundary (config, flow params, the events array, the `ContactMessage`
// JSON the pairing codec entry points exchange). Those payloads travel as
// bytes, not a JS string — the host functions read `ArrayBuffer`/typed-array
// arguments and hand back `ArrayBuffer` results (see `ProtocolHost.cpp`'s
// `bytesToArrayBuffer`). `TextDecoder`/`TextEncoder` are not declared as
// ambient globals under this package's `lib: ["ES2020"]` (no DOM lib) and the
// installed `@types/node` exposes them only from `node:util`, which does not
// exist in the Hermes runtime this code actually ships on. A small
// dependency-free codec avoids both problems.
// ---------------------------------------------------------------------------

export function utf8Encode(text: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = (code - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000;
        i++;
      }
    }
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return new Uint8Array(bytes);
}

export function utf8Decode(bytes: Uint8Array): string {
  let result = '';
  let i = 0;
  while (i < bytes.length) {
    const byte1 = bytes[i++];
    if (byte1 < 0x80) {
      result += String.fromCharCode(byte1);
    } else if (byte1 < 0xe0) {
      const byte2 = bytes[i++];
      result += String.fromCharCode(((byte1 & 0x1f) << 6) | (byte2 & 0x3f));
    } else if (byte1 < 0xf0) {
      const byte2 = bytes[i++];
      const byte3 = bytes[i++];
      result += String.fromCharCode(((byte1 & 0x0f) << 12) | ((byte2 & 0x3f) << 6) | (byte3 & 0x3f));
    } else {
      const byte2 = bytes[i++];
      const byte3 = bytes[i++];
      const byte4 = bytes[i++];
      const code =
        (((byte1 & 0x07) << 18) | ((byte2 & 0x3f) << 12) | ((byte3 & 0x3f) << 6) | (byte4 & 0x3f)) -
        0x10000;
      result += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    }
  }
  return result;
}

export function jsonToBytes(value: unknown): Uint8Array {
  return utf8Encode(JSON.stringify(value));
}

export function jsonFromBytes(buffer: ArrayBuffer): unknown {
  return JSON.parse(utf8Decode(new Uint8Array(buffer)));
}
