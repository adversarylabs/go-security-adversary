import { domain } from "./domain.js";
import { descendants, parseGo, sourceText } from "./parser.js";
import { selfRateLimitDenialSignals } from "./self-rate-limit.js";
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
          signals.push(...secretQueryExposureSignals(file, tree.rootNode));
          const currentSymlinkSignals = symlinkEscapeSignals(file, tree.rootNode);
          if (file.previous === undefined || currentSymlinkSignals.length === 0) {
            signals.push(...currentSymlinkSignals);
          } else {
            const previousTree = await parseGo(file.previous);
            try {
              const previousFile: SourceRevision = {
                path: file.path,
                current: file.previous,
                changedLines: new Set(),
                status: "repository",
              };
              const previousIdentities = new Set(
                symlinkEscapeSignals(previousFile, previousTree.rootNode)
                  .map((signal) => String(signal.data.identity)),
              );
              signals.push(...currentSymlinkSignals.filter((signal) =>
                !previousIdentities.has(String(signal.data.identity))));
            } finally {
              previousTree.delete();
            }
          }
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

  signals.push(...await selfRateLimitDenialSignals(discovery.files));

  return {
    mode: discovery.mode,
    ...(discovery.base === undefined ? {} : { base: discovery.base }),
    filesScanned: discovery.files.length,
    signals: signals.sort(byLocation),
    positives: positives.sort(byLocation),
    parseErrors: parseErrors.sort((left, right) => left.path.localeCompare(right.path)),
  };
}

function symlinkEscapeSignals(file: SourceRevision, root: Node): Signal[] {
  if (file.path.endsWith("_test.go") || isObviousSymlinkTestSupportPath(file.path)) return [];
  const source = file.current;
  const signals: Signal[] = [];
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
  ];
  for (const fn of functions) {
    const nameNode = fn.childForFieldName("name");
    const functionName = nameNode === null ? "anonymous" : sourceText(nameNode, source);
    const calls = descendants(fn, "call_expression")
      .filter((call) => belongsDirectlyToFunction(call, fn))
      .sort((left, right) => left.startIndex - right.startIndex);
    const guards = descendants(fn, "if_statement")
      .filter((guard) => belongsDirectlyToFunction(guard, fn));
    for (const lstat of calls) {
      const callable = lstat.childForFieldName("function");
      const args = lstat.childForFieldName("arguments")?.namedChildren ?? [];
      if (callable === null || sourceText(callable, source).replace(/\s/g, "") !== "os.Lstat" || args.length !== 1) continue;
      if (hasAncestorBefore(lstat, "for_statement", fn)) continue;
      const info = assignedFirstResult(lstat, source);
      if (info === undefined) continue;
      const guard = guards.find((candidate) => {
        if (candidate.startIndex <= lstat.endIndex) return false;
        const condition = candidate.childForFieldName("condition");
        const consequence = candidate.childForFieldName("consequence");
        if (condition === null || consequence === null) return false;
        const conditionText = sourceText(condition, source).replace(/\s/g, "");
        return conditionText.includes(`${info}.Mode()`) && conditionText.includes("os.ModeSymlink") &&
          blockHasDirectReturn(consequence);
      });
      if (guard === undefined) continue;
      const path = normalizedExpression(sourceText(args[0]!, source));
      const sink = calls.find((candidate) =>
        candidate.startIndex > guard.endIndex && sinkUsesPath(candidate, path, source));
      if (sink === undefined) continue;
      if (/^[A-Za-z_]\w*$/.test(path) && identifierAssignedBetween(fn, path, lstat.endIndex, sink.startIndex, source)) continue;
      if (identifierAssignedBetween(fn, info, lstat.endIndex, guard.startIndex, source)) continue;
      const evidence = [lstat, guard, sink];
      const anchor = evidence.find((node) =>
        changed(file, node.startPosition.row + 1, node.endPosition.row + 1));
      if (anchor === undefined) continue;
      signals.push({
        ruleId: "go-security.path.symlink-escape",
        path: file.path,
        line: anchor.startPosition.row + 1,
        endLine: anchor.endPosition.row + 1,
        message: `os.Lstat(${sourceText(args[0]!, source)}) checks only the final path component before the same path is mounted or opened; an intermediate symlink can escape the intended root.`,
        snippet: sourceText(anchor, source).trim().slice(0, 300),
        data: {
          guardedPath: sourceText(args[0]!, source).trim(),
          identity: `${functionName}|${path}|${sourceText(sink.childForFieldName("function")!, source).replace(/\s/g, "")}`,
        },
      });
    }
  }
  return signals;
}

function identifierAssignedBetween(
  fn: Node,
  name: string,
  after: number,
  before: number,
  source: string,
): boolean {
  return [
    ...descendants(fn, "short_var_declaration"),
    ...descendants(fn, "assignment_statement"),
  ].some((assignment) =>
    belongsDirectlyToFunction(assignment, fn) && assignment.startIndex > after && assignment.endIndex < before &&
    directIdentifiers(assignment.childForFieldName("left"), source).includes(name));
}

function isObviousSymlinkTestSupportPath(path: string): boolean {
  const parts = path.replaceAll("\\", "/").toLowerCase().split("/");
  if (parts.some((part) => /^(?:fake|fakes|fixture|fixtures|mock|mocks|testdata)$/.test(part))) return true;
  const filename = parts.at(-1) ?? "";
  return /^(?:mock|fake)_.+\.go$/.test(filename) || /\.(?:mock|fake)\.go$/.test(filename);
}

function blockHasDirectReturn(block: Node): boolean {
  const statements = block.namedChildren.find((node) => node.type === "statement_list");
  return statements?.namedChildren.some((node) => node.type === "return_statement") ?? false;
}

function assignedFirstResult(call: Node, source: string): string | undefined {
  let assignment = call.parent;
  while (assignment !== null && assignment.type !== "short_var_declaration" && assignment.type !== "assignment_statement") {
    if (assignment.type === "expression_statement" || assignment.type === "statement_list") return undefined;
    assignment = assignment.parent;
  }
  if (assignment === null) return undefined;
  const left = assignment.childForFieldName("left")?.namedChildren ?? [];
  const right = assignment.childForFieldName("right")?.namedChildren ?? [];
  if (left.length === 0 || right.length === 0) return undefined;
  const resultIndex = right.length === 1 ? 0 : right.findIndex((node) =>
    call.startIndex >= node.startIndex && call.endIndex <= node.endIndex);
  const result = left[resultIndex];
  return result?.type === "identifier" ? sourceText(result, source) : undefined;
}

function sinkUsesPath(call: Node, path: string, source: string): boolean {
  const callable = call.childForFieldName("function");
  const args = call.childForFieldName("arguments")?.namedChildren ?? [];
  if (callable === null || args.length === 0) return false;
  const name = sourceText(callable, source).replace(/\s/g, "");
  const equalsPath = (node: Node | undefined) =>
    node !== undefined && normalizedExpression(sourceText(node, source)) === path;
  if (/^(?:unix|syscall|mount)\.Mount$/.test(name)) return equalsPath(args[0]);
  if (/^os\.(?:Open|OpenFile|ReadFile|WriteFile|Create)$/.test(name)) return equalsPath(args[0]);
  if (name === "http.ServeFile") return equalsPath(args[2]);
  if (name === "exec.Command" || name === "exec.CommandContext") {
    const commandIndex = name === "exec.CommandContext" ? 1 : 0;
    if (!/^["`]mount["`]$/.test(sourceText(args[commandIndex]!, source).trim())) return false;
    return args.slice(commandIndex + 1).some(equalsPath);
  }
  return false;
}

function normalizedExpression(value: string): string {
  return stripOuterParentheses(value).replace(/\s/g, "");
}

function hasAncestorBefore(node: Node, type: string, boundary: Node): boolean {
  for (let parent = node.parent; parent !== null && parent.id !== boundary.id; parent = parent.parent) {
    if (parent.type === type) return true;
  }
  return false;
}

interface SecretQueryMutation {
  query: string;
  key: string;
  value: string;
  node: Node;
}

interface SecretURLFlow {
  url: string;
  mutation: SecretQueryMutation;
  rawQuery: Node;
}

interface HTTPErrorFlow extends SecretURLFlow {
  request?: string;
  requestNode?: Node;
  httpNode: Node;
  error: string;
}

function secretQueryExposureSignals(file: SourceRevision, root: Node): Signal[] {
  if (file.path.endsWith("_test.go")) return [];
  const httpAliases = netHTTPAliases(root, file.current);
  if (httpAliases.size === 0) return [];
  const signals: Signal[] = [];
  const seen = new Set<string>();
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
  ];

  for (const fn of functions) {
    const calls = descendants(fn, "call_expression")
      .filter((node) => belongsDirectlyToFunction(node, fn))
      .sort((left, right) => left.startIndex - right.startIndex);
    const assignments = [
      ...descendants(fn, "short_var_declaration"),
      ...descendants(fn, "assignment_statement"),
    ]
      .filter((node) => belongsDirectlyToFunction(node, fn))
      .sort((left, right) => left.startIndex - right.startIndex);
    const httpClients = netHTTPClientExpressions(fn, assignments, httpAliases, file.current);

    const mutations = new Map<string, SecretQueryMutation>();
    for (const call of calls) {
      const callable = call.childForFieldName("function");
      const args = call.childForFieldName("arguments");
      if (callable === null || args === null || args.namedChildCount < 2) continue;
      const method = sourceText(callable, file.current).replace(/\s/g, "");
      const match = method.match(/^([A-Za-z_]\w*)\.(?:Set|Add)$/);
      if (match === null) continue;
      const keyNode = args.namedChild(0);
      const valueNode = args.namedChild(1);
      if (keyNode === null || valueNode === null) continue;
      const key = stringLiteralValue(keyNode, file.current);
      const value = sourceText(valueNode, file.current).trim();
      if (key === undefined || !isSecretQueryKey(key) || !isSecretLikeExpression(value)) continue;
      mutations.set(match[1]!, { query: match[1]!, key, value, node: call });
    }

    const urls = new Map<string, SecretURLFlow>();
    for (const assignment of assignments) {
      const left = singleExpression(assignment.childForFieldName("left"));
      const right = singleExpression(assignment.childForFieldName("right"));
      if (left === null || right === null) continue;
      const urlMatch = sourceText(left, file.current).replace(/\s/g, "").match(/^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.RawQuery$/);
      const queryMatch = sourceText(right, file.current).replace(/\s/g, "").match(/^([A-Za-z_]\w*)\.Encode\(\)$/);
      if (urlMatch === null || queryMatch === null) continue;
      const mutation = mutations.get(queryMatch[1]!);
      if (mutation === undefined || mutation.node.startIndex >= assignment.startIndex) continue;
      urls.set(urlMatch[1]!, { url: urlMatch[1]!, mutation, rawQuery: assignment });
    }

    for (const url of urls.values()) {
      for (const flow of httpErrorFlows(assignments, url, httpAliases, httpClients, file.current)) {
        const sink = firstHTTPExposureSink(fn, calls, flow, file.current);
        if (sink === undefined) continue;
        const anchors = [flow.mutation.node, flow.rawQuery, flow.requestNode, flow.httpNode, sink]
          .filter((node): node is Node => node !== undefined);
        const anchor = anchors.find((node) => changed(
          file,
          node.startPosition.row + 1,
          node.endPosition.row + 1,
        ));
        if (anchor === undefined) continue;
        const identity = `${flow.mutation.node.startIndex}:${sink.startIndex}`;
        if (seen.has(identity)) continue;
        seen.add(identity);
        signals.push({
          ruleId: "go-security.token-in-url",
          path: file.path,
          line: anchor.startPosition.row + 1,
          endLine: anchor.endPosition.row + 1,
          message: `${flow.mutation.key} carries ${flow.mutation.value} in an HTTP query string whose request URL can escape through ${exposureDescription(sink, flow.error, file.current)}.`,
          snippet: sourceText(anchor, file.current).trim().slice(0, 300),
          data: {
            queryKey: flow.mutation.key,
            secretExpression: flow.mutation.value,
            url: flow.url,
            error: flow.error,
            queryLine: flow.mutation.node.startPosition.row + 1,
            httpLine: flow.httpNode.startPosition.row + 1,
            sinkLine: sink.startPosition.row + 1,
          },
        });
      }
    }
  }
  return signals;
}

function httpErrorFlows(
  assignments: Node[],
  url: SecretURLFlow,
  httpAliases: Set<string>,
  httpClients: Set<string>,
  source: string,
): HTTPErrorFlow[] {
  const requestOrigins = new Map<string, Node>();
  const requestFromURL = url.url.match(/^([A-Za-z_]\w*)\.URL$/)?.[1];
  if (requestFromURL !== undefined) requestOrigins.set(requestFromURL, url.rawQuery);

  for (const assignment of assignments) {
    if (assignment.startIndex <= url.rawQuery.startIndex) continue;
    const right = singleExpression(assignment.childForFieldName("right"));
    if (right?.type !== "call_expression") continue;
    const callable = right.childForFieldName("function");
    const args = right.childForFieldName("arguments");
    if (callable === null || args === null) continue;
    const name = sourceText(callable, source).replace(/\s/g, "");
    const offset = [...httpAliases].some((alias) => name === `${alias}.NewRequest`) ? 1
      : [...httpAliases].some((alias) => name === `${alias}.NewRequestWithContext`) ? 2
        : undefined;
    if (offset === undefined) continue;
    const endpoint = args.namedChild(offset);
    const names = directIdentifiers(assignment.childForFieldName("left"), source);
    if (endpoint !== null && names.length > 0 && expressionUsesURL(endpoint, url.url, source)) {
      requestOrigins.set(names[0]!, right);
    }
  }

  const flows: HTTPErrorFlow[] = [];
  for (const assignment of assignments) {
    if (assignment.startIndex <= url.rawQuery.startIndex) continue;
    const right = singleExpression(assignment.childForFieldName("right"));
    if (right?.type !== "call_expression") continue;
    const callable = right.childForFieldName("function");
    const args = right.childForFieldName("arguments");
    const names = directIdentifiers(assignment.childForFieldName("left"), source);
    if (callable === null || args === null || names.length < 2) continue;
    const name = sourceText(callable, source).replace(/\s/g, "");
    const error = names.at(-1)!;
    if (error === "_") continue;

    const method = name.match(/^(.*)\.(Get|Post|PostForm)$/);
    const directHTTP = method !== null && (
      httpClients.has(method[1]!) ||
      [...httpAliases].includes(method[1]!)
    );
    const endpoint = args.namedChild(0);
    if (directHTTP && endpoint !== null && expressionUsesURL(endpoint, url.url, source)) {
      flows.push({ ...url, httpNode: right, error });
      continue;
    }

    const doReceiver = name.match(/^(.*)\.Do$/)?.[1];
    if (doReceiver === undefined || !httpClients.has(doReceiver)) continue;
    const requestArg = args.namedChild(0);
    if (requestArg === null) continue;
    const request = sourceText(requestArg, source).trim();
    const requestNode = requestOrigins.get(request);
    if (requestNode !== undefined) {
      flows.push({ ...url, request, requestNode, httpNode: right, error });
    }
  }
  return flows;
}

function netHTTPClientExpressions(
  fn: Node,
  assignments: Node[],
  httpAliases: Set<string>,
  source: string,
): Set<string> {
  const clients = new Set<string>();
  for (const alias of httpAliases) clients.add(`${alias}.DefaultClient`);

  for (const parameter of descendants(fn, "parameter_declaration")) {
    if (!belongsDirectlyToFunction(parameter, fn)) continue;
    const type = parameter.childForFieldName("type");
    if (type === null) continue;
    const typeText = sourceText(type, source).replace(/\s/g, "");
    if (![...httpAliases].some((alias) => typeText === `*${alias}.Client` || typeText === `${alias}.Client`)) continue;
    for (const name of directIdentifiers(parameter.childForFieldName("name"), source)) clients.add(name);
  }

  for (const assignment of assignments) {
    const right = singleExpression(assignment.childForFieldName("right"));
    if (right === null) continue;
    const value = sourceText(right, source).replace(/\s/g, "");
    if (![...httpAliases].some((alias) =>
      value.startsWith(`&${alias}.Client{`) || value.startsWith(`${alias}.Client{`) || value === `${alias}.DefaultClient`
    )) continue;
    const names = directIdentifiers(assignment.childForFieldName("left"), source);
    if (names.length === 1) clients.add(names[0]!);
  }
  return clients;
}

function firstHTTPExposureSink(
  fn: Node,
  calls: Node[],
  flow: HTTPErrorFlow,
  source: string,
): Node | undefined {
  const afterHTTP = (node: Node) => node.startIndex > flow.httpNode.endIndex;
  for (const call of calls.filter(afterHTTP)) {
    const callable = call.childForFieldName("function");
    const args = call.childForFieldName("arguments");
    if (callable === null || args === null) continue;
    const name = sourceText(callable, source).replace(/\s/g, "");
    const wrapsError = /(?:^|\.)(?:Errorf|Wrap|Wrapf)$/.test(name);
    const logsValue = /(?:^|\.)(?:Print|Printf|Println|Debug|Info|Warn|Error)$/.test(name);
    if ((!wrapsError || !hasAncestor(call, "return_statement", fn)) && !logsValue) continue;
    const text = sourceText(args, source);
    if (
      (referencesIdentifier(text, flow.error) &&
        !identifierReassignedBetween(fn, flow.error, flow.httpNode.endIndex, call.startIndex, source)) ||
      referencesRequestURL(text, flow)
    ) return call;
  }

  for (const statement of descendants(fn, "return_statement")) {
    if (!belongsDirectlyToFunction(statement, fn) || !afterHTTP(statement)) continue;
    if (
      referencesIdentifier(sourceText(statement, source), flow.error) &&
      !identifierReassignedBetween(fn, flow.error, flow.httpNode.endIndex, statement.startIndex, source)
    ) return statement;
  }
  return undefined;
}

function identifierReassignedBetween(
  fn: Node,
  identifier: string,
  after: number,
  before: number,
  source: string,
): boolean {
  for (const type of ["short_var_declaration", "assignment_statement", "var_spec"]) {
    for (const node of descendants(fn, type)) {
      if (!belongsDirectlyToFunction(node, fn) || node.startIndex <= after || node.startIndex >= before) continue;
      const left = node.childForFieldName(type === "var_spec" ? "name" : "left");
      if (directIdentifiers(left, source).includes(identifier)) return true;
    }
  }
  return false;
}

function hasAncestor(node: Node, type: string, boundary: Node): boolean {
  for (let parent = node.parent; parent !== null && parent.id !== boundary.id; parent = parent.parent) {
    if (parent.type === type) return true;
  }
  return false;
}

function expressionUsesURL(node: Node, url: string, source: string): boolean {
  const text = sourceText(node, source).replace(/\s/g, "");
  const escaped = escapeRegExp(url);
  return new RegExp(`^(?:${escaped}|${escaped}\\.String\\(\\)|${escaped}\\.RequestURI\\(\\))$`).test(text);
}

function referencesIdentifier(text: string, identifier: string): boolean {
  return new RegExp(`\\b${escapeRegExp(identifier)}\\b`).test(text);
}

function referencesRequestURL(text: string, flow: HTTPErrorFlow): boolean {
  if (flow.request !== undefined && new RegExp(`\\b${escapeRegExp(flow.request)}\\.URL\\b`).test(text)) return true;
  return new RegExp(`\\b${escapeRegExp(flow.url)}(?:\\.String\\(\\)|\\b)`).test(text);
}

function exposureDescription(sink: Node, error: string, source: string): string {
  const text = sourceText(sink, source);
  if (sink.type === "return_statement") return `returned HTTP error ${error}`;
  if (referencesIdentifier(text, error)) return `logged or wrapped HTTP error ${error}`;
  return "logged request URL";
}

function isSecretQueryKey(key: string): boolean {
  return /^(?:(?:access|refresh|id|auth|api)[_-]?token|token|api[_-]?key|apikey|client[_-]?secret|secret|password|credential|signature|sig)$/i.test(key);
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
