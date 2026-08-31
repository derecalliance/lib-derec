// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

import {Platform} from 'react-native';

// The emulator reaches the host through the 10.0.2.2 alias; the simulator
// shares the host's loopback.
const HOST = Platform.OS === 'android' ? '10.0.2.2' : 'localhost';
const PORT = 8099;

/**
 * Sends a line to the collector `smoke-tests/react-native/run_test.sh` runs.
 *
 * React Native routes `console.log` to the debugger rather than to Metro's
 * stdout, so a run can pass or fail with nothing reaching any log the script
 * can read. An HTTP POST is observable from the host, and identically on both
 * platforms.
 */
export async function report(line: string): Promise<void> {
  try {
    await fetch(`http://${HOST}:${PORT}/`, {method: 'POST', body: line});
  } catch {
    // The on-screen render is the fallback for a human watching the device.
  }
}

let queue: string[] = [];
let flushing: ReturnType<typeof setTimeout> | undefined;

function flush(): void {
  flushing = undefined;
  if (queue.length === 0) {
    return;
  }
  const batch = queue.join('\n');
  queue = [];
  void report(batch);
}

/**
 * Queues a line, batching sends.
 *
 * The ported suites narrate every step, and one request per line would make
 * the network round trips, rather than the protocol, dominate the run.
 */
export function trace(line: string): void {
  queue.push(line);
  if (flushing === undefined) {
    flushing = setTimeout(flush, 250);
  }
}

/** Sends anything still queued and resolves once it is on the wire. */
export async function drain(): Promise<void> {
  if (flushing !== undefined) {
    clearTimeout(flushing);
    flushing = undefined;
  }
  if (queue.length > 0) {
    const batch = queue.join('\n');
    queue = [];
    await report(batch);
  }
}

/**
 * Mirrors console output to the collector.
 *
 * The ported suites already narrate each flow through `console.log`; without
 * this that narration is invisible to CI, and a failure reports only its final
 * message with no indication of which flow it came from.
 */
export function forwardConsole(): void {
  const original = console.log.bind(console);
  console.log = (...args: unknown[]): void => {
    original(...args);
    trace(args.map((a) => String(a)).join(' '));
  };
}
