import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const backendDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const scriptPath = path.join(backendDirectory, "scripts", "migrate-to-s3.js");

const runMigrationScript = (...args) =>
  spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: backendDirectory,
    encoding: "utf8",
  });

test("migration apply requires an explicit completed backup ID", () => {
  const result = runMigrationScript("--apply");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /"errorCode":"BACKUP_REQUIRED"/);
  assert.doesNotMatch(result.stderr, /MONGO_URI_MISSING/);
});

test("migration rejects conflicting modes before connecting to services", () => {
  const result = runMigrationScript("--dry-run", "--backup");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /"errorCode":"INVALID_ARGUMENTS"/);
  assert.doesNotMatch(result.stderr, /MONGO_URI_MISSING/);
});
