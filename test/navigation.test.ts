import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { openRepoIndex } from "@adversarylabs/sdk";
import { productionImporters } from "../src/navigation.js";

async function writeIndex(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, "meta.json"),
    JSON.stringify({
      schemaVersion: "v1",
      fingerprint: "test",
      repoPath: "/fixture",
      fileCount: 3,
      edgeCount: 1,
    }) + "\n",
  );
  await writeFile(
    join(dir, "files.jsonl"),
    [
      JSON.stringify({ path: "pkg/weak/tls.go", language: "go", size: 1, hash: "a" }),
      JSON.stringify({ path: "pkg/api/server.go", language: "go", size: 1, hash: "b" }),
      JSON.stringify({ path: "pkg/weak/tls_test.go", language: "go", size: 1, hash: "c" }),
    ].join("\n") + "\n",
  );
  await writeFile(
    join(dir, "edges.jsonl"),
    [
      JSON.stringify({ from: "pkg/api/server.go", to: "pkg/weak", kind: "import" }),
      JSON.stringify({ from: "pkg/weak/tls_test.go", to: "pkg/weak", kind: "import" }),
    ].join("\n") + "\n",
  );
}

test("productionImporters uses shared repo index edges and skips test importers", async () => {
  const dir = join(tmpdir(), `go-security-nav-${Date.now()}`);
  await writeIndex(dir);
  const index = await openRepoIndex(dir);
  const importers = await productionImporters(index, "pkg/weak/tls.go");
  assert.deepEqual(importers, ["pkg/api/server.go"]);
});
