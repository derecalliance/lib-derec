// Runs the web smoke suite in headless Chromium against a served build, the
// way an application loads the package: the page fetches the `.wasm` over
// HTTP and runs as an ES module. Exits non-zero unless the page reports
// `DEREC_SMOKE_RESULT: PASS`.

import { chromium } from "playwright";

const url = process.argv[2];
if (!url) {
  console.error("usage: node run.mjs <url>");
  process.exit(2);
}

const TIMEOUT_MS = 180_000;
const RESULT = "DEREC_SMOKE_RESULT: ";

const browser = await chromium.launch();
let outcome;
try {
  const page = await browser.newPage();

  outcome = await new Promise((resolve) => {
    const timer = setTimeout(
      () => resolve({ pass: false, reason: `no result within ${TIMEOUT_MS / 1000}s` }),
      TIMEOUT_MS,
    );
    const finish = (result) => {
      clearTimeout(timer);
      resolve(result);
    };

    page.on("console", (message) => {
      const text = message.text();
      if (text.startsWith(RESULT)) {
        const verdict = text.slice(RESULT.length);
        finish({ pass: verdict === "PASS", reason: verdict.replace(/^FAIL\s*/, "") });
        return;
      }
      (message.type() === "error" ? console.error : console.log)(text);
    });
    page.on("pageerror", (error) => {
      finish({ pass: false, reason: `uncaught page error: ${error.stack ?? error.message}` });
    });
    page.on("requestfailed", (request) => {
      finish({
        pass: false,
        reason: `request failed: ${request.url()} (${request.failure()?.errorText})`,
      });
    });

    page.goto(url).catch((error) => {
      finish({ pass: false, reason: `could not load ${url}: ${error.message}` });
    });
  });
} finally {
  await browser.close();
}

if (outcome.pass) {
  console.log(`${RESULT}PASS`);
  process.exit(0);
}
console.error(`${RESULT}FAIL ${outcome.reason}`);
process.exit(1);
