/**
 * @format
 *
 * The scaffolder's default test rendered `<App />`, which is no longer a
 * meaningful unit test here: mounting the component starts the whole smoke
 * suite, and that suite only means anything against the real native module on
 * a device. Under Jest there is no JSI host object, so the render would either
 * fail on the missing module or, worse, pass while proving nothing.
 *
 * The scenarios are exercised by `smoke-tests/react-native/run_test.sh`; the
 * SDK's own logic is covered by the unit tests in
 * `packages/react-native/__tests__/`.
 */

import {report} from '../src/report';

test('the reporter is importable without a native module', () => {
  // Guards the one part of the app that must work before the SDK loads: if
  // reporting could not be imported, an install failure would be invisible to
  // the runner rather than reported as a failure.
  expect(typeof report).toBe('function');
});
