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
          signals.push(...authenticationCookieHttpOnlySignals(file, tree.rootNode));
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

function authenticationCookieHttpOnlySignals(file: SourceRevision, root: Node): Signal[] {
  const signals: Signal[] = [];
  const seen = new Set<number>();
  const httpAliases = netHTTPAliases(root, file.current);
  if (httpAliases.size === 0) return [];
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
  ];

  for (const fn of functions) {
    for (const call of descendants(fn, "call_expression")) {
      if (!belongsDirectlyToFunction(call, fn)) continue;
      const callable = call.childForFieldName("function");
      const args = call.childForFieldName("arguments");
      if (callable === null || args === null || !isHTTPSetCookie(callable, httpAliases, file.current)) continue;
      const cookieArg = args.namedChild(args.namedChildCount - 1);
      if (cookieArg === null) continue;

      const alias = cookieAliasArgument(cookieArg, file.current);
      const origin = alias === undefined
        ? directCookieLiteralOrigin(cookieArg, httpAliases, file.current)
        : latestCookieLiteralForAlias(fn, alias, call.startIndex, httpAliases, file.current);
      if (origin === undefined || seen.has(origin.literal.startIndex)) continue;
      const literal = origin.literal;

      const nameField = effectiveCookieField(fn, alias, origin.at, call.startIndex, literal, "Name", file.current);
      if (nameField === undefined) continue;
      const cookieName = stringLiteralValue(nameField.value, file.current);
      if (cookieName === undefined || !isAuthenticationCookieName(cookieName)) continue;

      const valueField = effectiveCookieField(fn, alias, origin.at, call.startIndex, literal, "Value", file.current);
      if (valueField === undefined || stringLiteralValue(valueField.value, file.current) === "") continue;

      const maxAge = effectiveCookieField(fn, alias, origin.at, call.startIndex, literal, "MaxAge", file.current);
      if (maxAge !== undefined && isNegativeIntegerLiteral(sourceText(maxAge.value, file.current))) continue;

      const httpOnly = effectiveCookieField(fn, alias, origin.at, call.startIndex, literal, "HttpOnly", file.current);
      if (httpOnly !== undefined) {
        const value = sourceText(httpOnly.value, file.current).trim();
        if (value !== "false") continue;
      }

      const literalStart = literal.startPosition.row + 1;
      const literalEnd = literal.endPosition.row + 1;
      const callStart = call.startPosition.row + 1;
      const callEnd = call.endPosition.row + 1;
      const fieldChanged = [nameField, valueField, maxAge, httpOnly].some((field) =>
        field !== undefined && changed(file, field.field.startPosition.row + 1, field.value.endPosition.row + 1)
      );
      if (!changed(file, literalStart, literalEnd) && !changed(file, callStart, callEnd) && !fieldChanged) continue;

      seen.add(literal.startIndex);
      const line = (httpOnly?.field ?? nameField.field).startPosition.row + 1;
      signals.push({
        ruleId: "go-security.cookie.auth-httponly",
        path: file.path,
        line,
        message: `${cookieName} is emitted as an authentication cookie without HttpOnly: true.`,
        snippet: sourceText(literal, file.current).trim().slice(0, 300),
        data: { cookieName, httpOnly: httpOnly === undefined ? "omitted" : "false", setCookieLine: callStart },
      });
    }
  }
  return signals;
}

interface CookieLiteralOrigin {
  literal: Node;
  at: number;
}

function netHTTPAliases(root: Node, source: string): Set<string> {
  const aliases = new Set<string>();
  for (const spec of descendants(root, "import_spec")) {
    const path = spec.childForFieldName("path");
    if (path === null || stringLiteralValue(path, source) !== "net/http") continue;
    const name = spec.childForFieldName("name");
    const alias = name === null ? "http" : sourceText(name, source).trim();
    if (alias !== "." && alias !== "_") aliases.add(alias);
  }
  return aliases;
}

function isHTTPSetCookie(callable: Node, aliases: Set<string>, source: string): boolean {
  const text = sourceText(callable, source).replace(/\s/g, "");
  return [...aliases].some((alias) => text === `${alias}.SetCookie`);
}

function cookieAliasArgument(node: Node, source: string): string | undefined {
  if (node.type === "identifier") return sourceText(node, source);
  if (node.type !== "unary_expression" || !sourceText(node, source).trim().startsWith("&")) return undefined;
  const operand = node.childForFieldName("operand");
  return operand?.type === "identifier" ? sourceText(operand, source) : undefined;
}

function directCookieLiteralOrigin(
  node: Node,
  httpAliases: Set<string>,
  source: string,
): CookieLiteralOrigin | undefined {
  const literal = findHTTPCookieLiteral(node, httpAliases, source);
  return literal === undefined ? undefined : { literal, at: literal.startIndex };
}

function latestCookieLiteralForAlias(
  fn: Node,
  alias: string,
  before: number,
  httpAliases: Set<string>,
  source: string,
): CookieLiteralOrigin | undefined {
  let latest: { at: number; literal: Node | undefined } | undefined;
  const consider = (node: Node, left: Node | null, right: Node | null): void => {
    if (node.startIndex >= before || !directIdentifiers(left, source).includes(alias)) return;
    const expression = singleExpression(right);
    const literal = expression === null ? undefined : findHTTPCookieLiteral(expression, httpAliases, source);
    if (latest === undefined || latest.at < node.startIndex) latest = { at: node.startIndex, literal };
  };

  for (const node of descendants(fn, "short_var_declaration")) {
    if (belongsDirectlyToFunction(node, fn)) {
      consider(node, node.childForFieldName("left"), node.childForFieldName("right"));
    }
  }
  for (const node of descendants(fn, "assignment_statement")) {
    if (belongsDirectlyToFunction(node, fn)) {
      consider(node, node.childForFieldName("left"), node.childForFieldName("right"));
    }
  }
  for (const node of descendants(fn, "var_spec")) {
    if (belongsDirectlyToFunction(node, fn)) {
      consider(node, node.childForFieldName("name"), node.childForFieldName("value"));
    }
  }
  return latest?.literal === undefined ? undefined : { literal: latest.literal, at: latest.at };
}

function findHTTPCookieLiteral(node: Node, httpAliases: Set<string>, source: string): Node | undefined {
  const candidates = node.type === "composite_literal" ? [node] : descendants(node, "composite_literal");
  return candidates.find((candidate) => {
    const type = candidate.childForFieldName("type");
    if (type === null) return false;
    const text = sourceText(type, source).replace(/\s/g, "");
    return [...httpAliases].some((alias) => text === `${alias}.Cookie`);
  });
}

function effectiveCookieField(
  fn: Node,
  alias: string | undefined,
  after: number,
  before: number,
  literal: Node,
  fieldName: string,
  source: string,
): { field: Node; value: Node } | undefined {
  if (alias !== undefined) {
    const mutation = latestCookieFieldMutation(fn, alias, fieldName, after, before, source);
    if (mutation !== undefined) return mutation;
  }
  return cookieField(literal, fieldName, source);
}

function latestCookieFieldMutation(
  fn: Node,
  alias: string,
  fieldName: string,
  after: number,
  before: number,
  source: string,
): { field: Node; value: Node } | undefined {
  let latest: { at: number; field: Node; value: Node } | undefined;
  for (const assignment of descendants(fn, "assignment_statement")) {
    if (!belongsDirectlyToFunction(assignment, fn) || assignment.startIndex <= after || assignment.startIndex >= before) continue;
    const left = singleExpression(assignment.childForFieldName("left"));
    const right = singleExpression(assignment.childForFieldName("right"));
    const operator = assignment.childForFieldName("operator");
    if (left === null || right === null || operator === null || sourceText(operator, source) !== "=") continue;
    if (sourceText(left, source).replace(/\s/g, "") !== `${alias}.${fieldName}`) continue;
    if (latest === undefined || latest.at < assignment.startIndex) {
      latest = { at: assignment.startIndex, field: left, value: right };
    }
  }
  return latest === undefined ? undefined : { field: latest.field, value: latest.value };
}

function cookieField(
  literal: Node,
  fieldName: string,
  source: string,
): { field: Node; value: Node } | undefined {
  const body = literal.childForFieldName("body");
  if (body === null) return undefined;
  for (const element of body.namedChildren) {
    if (element.type !== "keyed_element") continue;
    const key = element.childForFieldName("key");
    const value = element.childForFieldName("value");
    if (key === null || value === null || sourceText(key, source).trim() !== fieldName) continue;
    return { field: key, value };
  }
  return undefined;
}

function stringLiteralValue(node: Node, source: string): string | undefined {
  const value = sourceText(node, source).trim();
  if (value.startsWith("`") && value.endsWith("`")) return value.slice(1, -1);
  if (!value.startsWith('"') || !value.endsWith('"')) return undefined;
  try {
    const decoded: unknown = JSON.parse(value);
    return typeof decoded === "string" ? decoded : undefined;
  } catch {
    return undefined;
  }
}

function isNegativeIntegerLiteral(source: string): boolean {
  let value = source.replace(/[\s_]/g, "");
  while (value.startsWith("(") && value.endsWith(")")) value = value.slice(1, -1);
  if (!value.startsWith("-")) return false;
  value = value.slice(1);
  while (value.startsWith("(") && value.endsWith(")")) value = value.slice(1, -1);
  return /^(?:0[xX][0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*|0[bB][01]*1[01]*|0[oO][0-7]*[1-7][0-7]*|[0-9]*[1-9][0-9]*)$/.test(value);
}

function isAuthenticationCookieName(name: string): boolean {
  const normalized = name.toLowerCase();
  if (/(?:csrf|xsrf|preference|setting|theme|display)/.test(normalized)) return false;
  return /(?:^|[-_.])(?:session(?:id|cookie)?|auth(?:entication|orization|token|cookie)?|login(?:cookie)?|(?:access|refresh|id)[-_]?token|token|credential)(?:$|[-_.])/
    .test(normalized);
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
