import { domain } from "./domain.js";
import { descendants, parseGo, sourceText } from "./parser.js";
import { type Analysis, type Discovery, type PositiveSignal, type Signal, type SourceRevision } from "./types.js";
import { type Node } from "web-tree-sitter";

export async function analyzeDiscovery(discovery: Discovery): Promise<Analysis> {
  const signals: Signal[] = [];
  const positives: PositiveSignal[] = [];
  const parseErrors: Analysis["parseErrors"] = [];

  for (const file of discovery.files) {
    try {
      if (file.path.endsWith(".go")) {
        const tree = await parseGo(file.current);
        try {
          if (tree.rootNode.hasError) throw new Error("Go source contains syntax errors");
          signals.push(...nilAttestationSubjectSignals(file, tree.rootNode));
          signals.push(...variableTimeCredentialComparisonSignals(file, tree.rootNode));
        } finally {
          tree.delete();
        }
      }
      const result = domain.analyze(file);
      signals.push(...result.signals.filter((item) => changed(file, item.line, item.endLine)));
      positives.push(...result.positives.filter((item) => changed(file, item.line)));
    } catch (error) {
      parseErrors.push({ path: file.path, message: error instanceof Error ? error.message : String(error) });
    }
  }

  return {
    mode: discovery.mode,
    ...(discovery.base === undefined ? {} : { base: discovery.base }),
    filesScanned: discovery.files.length,
    signals: signals.sort(byLocation),
    positives: positives.sort(byLocation),
    parseErrors: parseErrors.sort((left, right) => left.path.localeCompare(right.path)),
  };
}

function variableTimeCredentialComparisonSignals(file: SourceRevision, root: Node): Signal[] {
  if (file.path.endsWith("_test.go")) return [];
  const signals: Signal[] = [];
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
  ];

  for (const fn of functions) {
    const functionText = sourceText(fn, file.current);
    if (!/\.Header\.Get\s*\(/.test(functionText)) continue;

    const credentialAliases = credentialHeaderAliases(functionText);
    const nameNode = fn.childForFieldName("name");
    const functionName = nameNode === null ? "function" : sourceText(nameNode, file.current);

    for (const comparison of descendants(fn, "binary_expression")) {
      const leftNode = comparison.childForFieldName("left");
      const rightNode = comparison.childForFieldName("right");
      if (leftNode === null || rightNode === null) continue;
      const between = file.current.slice(leftNode.endIndex, rightNode.startIndex).trim();
      if (between !== "==" && between !== "!=") continue;

      const left = sourceText(leftNode, file.current).trim();
      const right = sourceText(rightNode, file.current).trim();
      const leftHeader = credentialHeader(left, credentialAliases);
      const rightHeader = credentialHeader(right, credentialAliases);
      const secret = leftHeader !== undefined && isSecretLikeExpression(right)
        ? right
        : rightHeader !== undefined && isSecretLikeExpression(left)
          ? left
          : undefined;
      const header = leftHeader ?? rightHeader;
      if (header === undefined || secret === undefined) continue;

      signals.push({
        ruleId: "go-security.crypto.constant-time",
        path: file.path,
        line: comparison.startPosition.row + 1,
        message:
          `${functionName} compares attacker-supplied ${header} to ${secret} with ${between}; use a constant-time credential comparison.`,
        snippet: sourceText(comparison, file.current).trim().slice(0, 300),
        data: { function: functionName, header, secret, operator: between },
      });
    }
  }
  return signals.filter((item) => changed(file, item.line, item.endLine));
}

function credentialHeaderAliases(functionText: string): Map<string, string> {
  const aliases = new Map<string, string>();
  const assignment = /\b([A-Za-z_]\w*)\s*(?::=|=(?!=))\s*([^\n;]*\.Header\.Get\s*\([^\n;]+\))/g;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(functionText)) !== null) {
    const alias = match[1];
    const expression = match[2];
    if (alias === undefined || expression === undefined) continue;
    const escapedAlias = escapeRegExp(alias);
    const assignments = functionText.match(new RegExp(`\\b${escapedAlias}\\s*(?::=|=(?!=))`, "g")) ?? [];
    if (assignments.length !== 1) continue;
    const header = credentialHeader(expression, new Map());
    if (header !== undefined) aliases.set(alias, header);
  }
  return aliases;
}

function credentialHeader(expression: string, aliases: Map<string, string>): string | undefined {
  const normalized = stripOuterParentheses(expression);
  const alias = aliases.get(normalized);
  if (alias !== undefined) return alias;
  const match = normalized.match(/\.Header\.Get\s*\(\s*["`]([^"`]+)["`]\s*\)/);
  const header = match?.[1];
  if (header === undefined) return undefined;
  const lower = header.toLowerCase();
  if (lower === "authorization" || lower === "proxy-authorization" ||
      /(?:signature|token|secret|api[-_]?key|webhook[-_]?key)/.test(lower)) {
    return header;
  }
  return undefined;
}

function isSecretLikeExpression(expression: string): boolean {
  const normalized = stripOuterParentheses(expression);
  if (!/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(normalized)) return false;
  const name = normalized.split(".").at(-1) ?? "";
  return /^(?:secret|token|signature|password|credential|apiKey|webhookKey|sharedKey)s?$/i.test(name) ||
    /(?:Secret|Token|Signature|Password|Credential|APIKey|WebhookKey|SharedKey)s?$/.test(name) ||
    /(?:^|_)(?:secret|token|signature|password|credential|api_?key|webhook_?key|shared_?key)s?$/i.test(name);
}

function stripOuterParentheses(expression: string): string {
  let normalized = expression.trim();
  while (normalized.startsWith("(") && normalized.endsWith(")")) {
    normalized = normalized.slice(1, -1).trim();
  }
  return normalized;
}

function nilAttestationSubjectSignals(file: SourceRevision, root: Node): Signal[] {
  const signals: Signal[] = [];
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
  ];

  for (const fn of functions) {
    const nameNode = fn.childForFieldName("name");
    if (nameNode === null) continue;
    const functionName = sourceText(nameNode, file.current);
    if (!/(?:verif|valid|claim)/i.test(functionName)) continue;

    const functionText = sourceText(fn, file.current);
    if (!/(?:attest|in[-_]?toto|statement)/i.test(functionText)) continue;

    for (const loop of descendants(fn, "for_statement")) {
      const loopText = sourceText(loop, file.current);
      const range = loopText.match(
        /^for\s+(?:[^,\n]+,\s*)?([A-Za-z_]\w*)\s*:=\s*range\s+([A-Za-z_][\w.]*Subject(?:s)?)\s*\{/,
      );
      const element = range?.[1];
      const collection = range?.[2];
      if (element === undefined || collection === undefined) continue;

      for (const condition of descendants(loop, "if_statement")) {
        const conditionText = sourceText(condition, file.current);
        const escapedElement = escapeRegExp(element);
        const nilGuard = new RegExp(
          `^if\\s+(?:${escapedElement}\\s*==\\s*nil|nil\\s*==\\s*${escapedElement})\\s*\\{`,
        );
        if (!nilGuard.test(conditionText)) continue;

        const continuation = descendants(condition, "continue_statement")[0];
        if (continuation === undefined) continue;

        signals.push({
          ruleId: "go-security.attestation.null-subject-skip",
          path: file.path,
          line: continuation.startPosition.row + 1,
          message:
            `${functionName} skips a nil element from ${collection}; a null subject makes the signed statement structurally invalid and should return an error.`,
          snippet: conditionText.trim().slice(0, 300),
          data: { function: functionName, element, collection },
        });
      }
    }
  }
  return signals;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function changed(file: SourceRevision, line: number, endLine = line): boolean {
  if (file.status === "repository" || file.status === "added") return true;
  for (let candidate = line; candidate <= endLine; candidate += 1) {
    if (file.changedLines.has(candidate)) return true;
  }
  return false;
}

function byLocation(left: { path: string; line: number }, right: { path: string; line: number }): number {
  return left.path.localeCompare(right.path) || left.line - right.line;
}
