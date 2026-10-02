#!/usr/bin/env bash
# Builds the web smoke suite against library/target/pkg-web, serves it, and
# runs it in headless Chromium. Exits non-zero unless every suite passes.
set -euo pipefail

cd "$(dirname "$0")"

npm ci --no-audit --no-fund
npx playwright install chromium
npm run build

port=$(node -e 'const s=require("net").createServer();s.listen(0,()=>{console.log(s.address().port);s.close();});')
url="http://127.0.0.1:${port}/"

npx vite preview --host 127.0.0.1 --port "${port}" --strictPort &
server=$!
trap 'kill "${server}" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  if curl --silent --fail --output /dev/null "${url}"; then
    break
  fi
  sleep 0.1
done

node run.mjs "${url}"
