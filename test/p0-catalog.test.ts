import assert from "node:assert/strict";
import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-security-p0-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

const review = async (rel: string) => {
  const root = await isolatedFixture(join(projectRoot, "fixtures", rel));
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
};

test("P0 catalog security rules detect vulnerable fixtures and stay quiet on clean", async () => {
  const cases = [
    { dir: "p0-tls", id: "go-security.tls-verification" },
    { dir: "p0-sql", id: "go-security.sql.string-concat" },
    { dir: "p0-shell", id: "go-security.cmd.shell" },
    { dir: "p0-path", id: "go-security.path.traversal" },
    { dir: "p0-symlink-escape", id: "go-security.path.symlink-escape" },
    { dir: "p0-zip", id: "go-security.archive.zip-slip" },
    { dir: "p0-crypto-math-rand", id: "go-security.crypto.math-rand" },
    { dir: "p0-crypto-hardcoded-key", id: "go-security.crypto.hardcoded-key" },
    { dir: "p0-crypto-static-nonce", id: "go-security.crypto.static-nonce" },
    { dir: "p0-pprof", id: "go-security.pprof.exposed" },
  ] as const;
  for (const c of cases) {
    const bad = await review(`${c.dir}/vulnerable`);
    assert.equal(
      bad.findings.some((f) => f.ruleId === c.id),
      true,
      `${c.id} missed; got ${bad.findings.map((f) => f.ruleId).join(",")}`,
    );
    const good = await review(`${c.dir}/clean`);
    assert.equal(
      good.findings.some((f) => f.ruleId === c.id),
      false,
      `${c.id} flagged clean; got ${good.findings.map((f) => f.ruleId).join(",")}`,
    );
  }
});
