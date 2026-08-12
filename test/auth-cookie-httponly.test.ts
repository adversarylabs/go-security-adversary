import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const ruleId = "go-security.cookie.auth-httponly";

async function review(source: string) {
  const root = await mkdtemp(join(tmpdir(), "go-security-cookie-"));
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "handler.go"), source);
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

test("flags a directly emitted session cookie without HttpOnly", async () => {
  const output = await review(`package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: true})
}
`);
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.match(finding.evidence[0]!.message ?? "", /session.*without HttpOnly/);
});

test("flags an aliased authentication cookie with HttpOnly false", async () => {
  const output = await review(`package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "github_login", Value: token, HttpOnly: false}
	http.SetCookie(w, cookie)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === ruleId), JSON.stringify(output.findings, null, 2));
});

test("accepts HttpOnly authentication cookies", async () => {
  const output = await review(`package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true})
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("accepts ordinary UI cookies and explicit deletion cookies", async () => {
  const output = await review(`package web
import "net/http"
func cookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "pending"})
	http.SetCookie(w, &http.Cookie{Name: "authorization_preferences", Value: "compact"})
	http.SetCookie(w, &http.Cookie{Name: "authenticated", Value: "true"})
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("accepts runtime policy and cookie literals that are not emitted", async () => {
  const output = await review(`package web
import "net/http"
func cookies(w http.ResponseWriter, token string, httpOnly bool) {
	_ = &http.Cookie{Name: "session", Value: token}
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: token, HttpOnly: httpOnly})
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("uses the latest alias assignment before SetCookie", async () => {
  const output = await review(`package web
import "net/http"
func cookies(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "session", Value: token}
	cookie = &http.Cookie{Name: "session", Value: token, HttpOnly: true}
	http.SetCookie(w, cookie)
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("uses HttpOnly field mutations before SetCookie", async () => {
  const output = await review(`package web
import "net/http"
func hardened(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "session", Value: token}
	cookie.HttpOnly = true
	http.SetCookie(w, cookie)
}
func weakened(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "session", Value: token, HttpOnly: true}
	cookie.HttpOnly = false
	http.SetCookie(w, cookie)
}
`);
  const findings = output.findings.filter((item) => item.ruleId === ruleId);
  assert.equal(findings.length, 1, JSON.stringify(output.findings, null, 2));
  assert.equal(findings[0]?.evidence[0]?.location?.line, 10);
});

test("diff mode anchors a changed HttpOnly field mutation", async () => {
  const current = `package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "session", Value: token, HttpOnly: true}
	cookie.HttpOnly = false
	http.SetCookie(w, cookie)
}
`;
  const mutationLine = current.split("\n").findIndex((line) => line.includes("cookie.HttpOnly")) + 1;
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "handler.go", current, changedLines: new Set([mutationLine]), status: "modified" }],
  });
  const signal = analysis.signals.find((item) => item.ruleId === ruleId);
  assert.equal(signal?.line, mutationLine);
});

test("uses mutated cookie names before SetCookie", async () => {
  const output = await review(`package web
import "net/http"
func credential(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "theme", Value: token}
	cookie.Name = "session"
	http.SetCookie(w, cookie)
}
func preference(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{Name: "session", Value: token}
	cookie.Name = "theme"
	http.SetCookie(w, cookie)
}
`);
  const findings = output.findings.filter((item) => item.ruleId === ruleId);
  assert.equal(findings.length, 1, JSON.stringify(output.findings, null, 2));
  assert.equal(findings[0]?.evidence[0]?.location?.line, 5);
});

test("follows a value cookie alias passed by address", async () => {
  const output = await review(`package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	cookie := http.Cookie{Name: "session", Value: token}
	http.SetCookie(w, &cookie)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === ruleId), JSON.stringify(output.findings, null, 2));
});

test("accepts every statically negative MaxAge as deletion", async () => {
  const output = await review(`package web
import "net/http"
func logout(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, MaxAge: -2})
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, MaxAge: -((0x2))})
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("recognizes an aliased net/http import", async () => {
  const output = await review(`package web
import stdhttp "net/http"
func login(w stdhttp.ResponseWriter, token string) {
	stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "session", Value: token})
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === ruleId), JSON.stringify(output.findings, null, 2));
});

test("diff mode requires the cookie literal or SetCookie call to change", async () => {
  const current = `package web
import "net/http"
func login(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}
`;
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "handler.go", current, changedLines: new Set([1]), status: "modified" }],
  });
  assert.equal(analysis.signals.some((item) => item.ruleId === ruleId), false);
});
