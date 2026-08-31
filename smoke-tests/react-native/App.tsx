// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// On-device smoke test entry point. Runs every scenario in sequence and logs a
// single sentinel line — `DEREC_SMOKE_RESULT: PASS` or
// `DEREC_SMOKE_RESULT: FAIL <reason>` — which
// `smoke-tests/react-native/run_test.sh` greps out of the device log. The on-screen
// list is for a human watching the simulator; the sentinel is what CI reads.

import React, {useEffect, useState} from 'react';
import {
  NativeModules,
  Platform,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
} from 'react-native';

import {drain, forwardConsole, report} from './src/report';
import {runPrimitives, runProtocol, runTeardownHazards} from './src/scenarios';

/** Whether the native module and its JSI host object actually arrived. A
 *  failure here is a wiring problem, not a protocol one, and says so. */
function nativeDiagnostics(): string {
  const host = (globalThis as Record<string, unknown>).__DeRec;
  const module = NativeModules.DeRec as Record<string, unknown> | undefined;
  return [
    `__DeRec=${host === undefined ? 'absent' : typeof host}`,
    `NativeModules.DeRec=${module === undefined ? 'absent' : 'present'}`,
    `install=${typeof module?.install}`,
    `modules=${Object.keys(NativeModules).length}`,
  ].join(' ');
}

const SCENARIOS: Array<[string, () => void | Promise<void>]> = [
  ['primitives', runPrimitives],
  ['protocol', runProtocol],
  ['teardown hazards', runTeardownHazards],
];

export default function App(): React.JSX.Element {
  const [log, setLog] = useState<string[]>([]);
  const [status, setStatus] = useState('running');

  useEffect(() => {
    (async () => {
      forwardConsole();
      const lines: string[] = [];
      try {
        for (const [name, run] of SCENARIOS) {
          await run();
          lines.push(`ok  ${name}`);
          setLog([...lines]);
        }
        setStatus('PASS');
        const pass = `DEREC_SMOKE_RESULT: PASS [${Platform.OS}]`;
        console.log(pass);
        await drain();
        await report(pass);
      } catch (error) {
        setStatus('FAIL');
        lines.push(String(error));
        setLog([...lines]);
        const stack = error instanceof Error && error.stack ? error.stack : '';
        const fail = `DEREC_SMOKE_RESULT: FAIL [${Platform.OS}] ${String(error)}`;
        console.log(fail);
        await drain();
        await report(`${fail}\n${stack}\n${nativeDiagnostics()}`);
      }
    })();
  }, []);

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.status}>{status}</Text>
        {log.map((line, index) => (
          <Text key={index} style={styles.line}>
            {line}
          </Text>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: {flex: 1},
  content: {padding: 16},
  status: {fontSize: 24, fontWeight: '700', marginBottom: 12},
  line: {fontFamily: 'Courier', fontSize: 12, marginBottom: 2},
});
