import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/index.ts";

const ruleId = "go-security.pkg.signature-bypass";

async function review(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "go-security-pkg-sig-"));
  await mkdir(root, { recursive: true });
  for (const [name, source] of Object.entries(files)) {
    await writeFile(join(root, name), source);
  }
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

test("flags zypper --no-gpg-checks on an installroot path", async () => {
  const output = await review({
    "install.go": `package distro

func flags(root string) []string {
	globalFlags := []string{"--non-interactive", "--gpg-auto-import-keys"}
	if root != "" {
		globalFlags = append(globalFlags, "--installroot", root)
		globalFlags = append(globalFlags, "--no-gpg-checks")
	}
	return globalFlags
}
`,
  });
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.match(finding.evidence[0]!.message ?? "", /--no-gpg-checks/);
});

test("flags yum --nogpgcheck and apt --allow-unauthenticated", async () => {
  const output = await review({
    "install.go": `package tools

import "os/exec"

func insecure(pkg string) {
	_ = exec.Command("yum", "install", "--nogpgcheck", pkg)
	_ = exec.Command("apt-get", "install", "--allow-unauthenticated", pkg)
	_ = exec.Command("rpm", "-i", "--nosignature", pkg)
}
`,
  });
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.equal(finding.evidence.length, 3, JSON.stringify(finding.evidence, null, 2));
});

test("stays quiet on comments and narrower unsigned-rpm allowance", async () => {
  const output = await review({
    "install.go": `package distro

func flags() []string {
	// --no-gpg-checks deliberately avoided; signed local files need a key.
	return []string{"--non-interactive", "--allow-unsigned-rpm"}
}
`,
  });
  assert.equal(
    output.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(output.findings, null, 2),
  );
});

test("stays quiet in _test.go even when the bypass flag is present", async () => {
  const output = await review({
    "install_test.go": `package distro

func example() []string {
	return []string{"--no-gpg-checks"}
}
`,
  });
  assert.equal(
    output.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(output.findings, null, 2),
  );
});
