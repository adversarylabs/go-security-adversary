import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);
const ruleId = "go-security.path.symlink-escape";

test("flags Lstat-plus-ModeSymlink before mount even when IsLocal is present", async () => {
  const output = await review({ "nodeserver.go": vulnerableSource() });
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.equal(finding.severity, "high");
  assert.match(finding.evidence[0]?.message ?? "", /final path component/i);
});

test("stays quiet on per-component Lstat and O_NOFOLLOW walks", async () => {
  const output = await review({
    "resolve.go": `package sample

import (
	"os"
	"path/filepath"
	"strings"
)

func resolve(root, sub string) (string, error) {
	current := root
	for _, part := range strings.Split(sub, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", os.ErrInvalid
		}
	}
	_, err := os.OpenFile(current, os.O_RDONLY|os.O_NOFOLLOW, 0)
	return current, err
}
`,
  });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false);
});

test("stays quiet on EvalSymlinks plus containment and on openat2", async () => {
  const output = await review({
    "eval.go": `package sample

import (
	"os"
	"path/filepath"
	"strings"
)

func resolve(root, mountPath string) (string, error) {
	resolved, err := filepath.EvalSymlinks(mountPath)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", os.ErrInvalid
	}
	return resolved, os.WriteFile(resolved, nil, 0o600)
}
`,
    "openat.go": `package sample

import "golang.org/x/sys/unix"

func openBeneath(dirfd int, name string) (int, error) {
	return unix.Openat2(dirfd, name, &unix.OpenHow{Flags: unix.O_RDONLY, Resolve: unix.RESOLVE_BENEATH})
}
`,
  });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false);
});

test("stays quiet in tests and when Lstat is only diagnostic", async () => {
  const output = await review({
    "nodeserver_test.go": vulnerableSource(),
    "stat.go": `package sample

import "os"

func describe(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return info.Mode()&os.ModeSymlink != 0, nil
}
`,
  });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false);
});

test("stays quiet when Lstat and open occur in unrelated functions", async () => {
  const output = await review({
    "unrelated.go": `package sample

import "os"

func isLink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil { return false, err }
	if info.Mode()&os.ModeSymlink != 0 { return true, nil }
	return false, nil
}

func readConfig() (*os.File, error) { return os.Open("/etc/sample.conf") }
`,
  });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false);
});

test("an unrelated safe resolver does not suppress a vulnerable mount", async () => {
  const source = vulnerableSource().replace(
    "func publish",
    `func safe(root, path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil { return "", err }
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) { return "", os.ErrInvalid }
	return resolved, nil
}

func publish`,
  ).replace('"path/filepath"', '"path/filepath"\n\t"strings"');
  const output = await review({ "nodeserver.go": source });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), true);
});

test("stays quiet when the path variable is replaced before the open", async () => {
  const output = await review({
    "reassigned.go": `package sample

import "os"

func openConfig(candidate string) (*os.File, error) {
	info, err := os.Lstat(candidate)
	if err != nil { return nil, err }
	if info.Mode()&os.ModeSymlink != 0 { return nil, os.ErrInvalid }
	candidate = "/etc/sample.conf"
	return os.Open(candidate)
}
`,
  });
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false);
});

test("diff locality ignores comments and unrelated edits beside a legacy Lstat gate", async () => {
  const root = await gitRepo({ "nodeserver.go": vulnerableSource() });
  await writeFile(join(root, "nodeserver.go"), vulnerableSource()
    .replace("package sample", "package sample\n\nvar unrelated = 1")
    .replace(`return exec.Command("mount", "--bind", mountPath, target).Run()`,
      `return exec.Command("mount", "--bind", mountPath, target).Run() // existing publish`));
  const unrelated = await changedReview(root);
  assert.equal(unrelated.findings.some((item) => item.ruleId === ruleId), false);
});

function vulnerableSource(): string {
  return `package sample

import (
	"os"
	"os/exec"
	"path/filepath"
)

func publish(root, sub, target string) error {
	mountPath := filepath.Join(root, sub)
	if !filepath.IsLocal(sub) {
		return os.ErrInvalid
	}
	info, err := os.Lstat(mountPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.ErrInvalid
	}
	return exec.Command("mount", "--bind", mountPath, target).Run()
}
`;
}

async function review(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "go-security-symlink-"));
  for (const [path, content] of Object.entries(files)) await writeFile(join(root, path), content);
  return createApp().run({ input: { source: { path: root } } });
}

async function changedReview(root: string) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: ["nodeserver.go"],
      },
    },
  });
}

async function gitRepo(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-security-symlink-git-"));
  await execute("git", ["init", "--quiet"], { cwd: root });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: root });
  await execute("git", ["config", "user.name", "Tests"], { cwd: root });
  for (const [path, content] of Object.entries(files)) await writeFile(join(root, path), content);
  await execute("git", ["add", "."], { cwd: root });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: root });
  return root;
}
