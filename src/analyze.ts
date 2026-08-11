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

    const credentialAliases = credentialHeaderAliases(fn, file.current);
    const nameNode = fn.childForFieldName("name");
    const functionName = nameNode === null ? "function" : sourceText(nameNode, file.current);

    for (const comparison of descendants(fn, "binary_expression")) {
      if (!belongsDirectlyToFunction(comparison, fn)) continue;
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

function credentialHeaderAliases(fn: Node, source: string): Map<string, string> {
  const writes = new Map<string, number[]>();
  const candidates: Array<{ alias: string; header: string; endIndex: number }> = [];

  const recordWrites = (names: string[], at: number): void => {
    for (const name of names) {
      if (name === "_") continue;
      const locations = writes.get(name) ?? [];
      locations.push(at);
      writes.set(name, locations);
    }
  };

  for (const node of descendants(fn, "short_var_declaration")) {
    if (!belongsDirectlyToFunction(node, fn)) continue;
    const names = directIdentifiers(node.childForFieldName("left"), source);
    recordWrites(names, node.startIndex);
    const expression = singleExpression(node.childForFieldName("right"));
    if (names.length !== 1 || expression === null) continue;
    const header = credentialHeader(sourceText(expression, source), new Map());
    if (header !== undefined) candidates.push({ alias: names[0]!, header, endIndex: node.endIndex });
  }

  for (const node of descendants(fn, "assignment_statement")) {
    if (!belongsDirectlyToFunction(node, fn)) continue;
    const names = directIdentifiers(node.childForFieldName("left"), source);
    recordWrites(names, node.startIndex);
    const operator = node.childForFieldName("operator");
    if (operator === null || sourceText(operator, source) !== "=") continue;
    const expression = singleExpression(node.childForFieldName("right"));
    if (names.length !== 1 || expression === null) continue;
    const header = credentialHeader(sourceText(expression, source), new Map());
    if (header !== undefined) candidates.push({ alias: names[0]!, header, endIndex: node.endIndex });
  }

  for (const node of descendants(fn, "var_spec")) {
    if (!belongsDirectlyToFunction(node, fn)) continue;
    const nameNode = node.childForFieldName("name");
    const names = directIdentifiers(nameNode, source);
    recordWrites(names, node.startIndex);
    const expression = singleExpression(node.childForFieldName("value"));
    if (names.length !== 1 || expression === null) continue;
    const header = credentialHeader(sourceText(expression, source), new Map());
    if (header !== undefined) candidates.push({ alias: names[0]!, header, endIndex: node.endIndex });
  }

  for (const type of ["inc_statement", "range_clause"]) {
    for (const node of descendants(fn, type)) {
      if (!belongsDirectlyToFunction(node, fn)) continue;
      const target = type === "range_clause" ? node.childForFieldName("left") : node.namedChild(0);
      recordWrites(directIdentifiers(target, source), node.startIndex);
    }
  }

  const aliases = new Map<string, string>();
  for (const candidate of candidates) {
    const laterMutation = (writes.get(candidate.alias) ?? []).some((at) => at >= candidate.endIndex);
    if (!laterMutation) aliases.set(candidate.alias, candidate.header);
  }
  return aliases;
}

function directIdentifiers(node: Node | null, source: string): string[] {
  if (node === null) return [];
  if (node.type === "identifier") return [sourceText(node, source)];
  if (node.type !== "expression_list") return [];
  const result: string[] = [];
  for (const child of node.namedChildren) {
    if (child.type !== "identifier") return [];
    result.push(sourceText(child, source));
  }
  return result;
}

function singleExpression(node: Node | null): Node | null {
  if (node === null) return null;
  if (node.type !== "expression_list") return node;
  return node.namedChildCount === 1 ? node.namedChild(0) : null;
}

function belongsDirectlyToFunction(node: Node, fn: Node): boolean {
  for (let parent = node.parent; parent !== null && parent.id !== fn.id; parent = parent.parent) {
    if (parent.type === "func_literal" || parent.type === "function_declaration" || parent.type === "method_declaration") {
      return false;
    }
  }
  return true;
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
