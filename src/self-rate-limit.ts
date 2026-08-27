import { dirname } from "node:path";
import { descendants, parseGo, sourceText } from "./parser.js";
import { type Signal, type SourceRevision } from "./types.js";
import { type Node } from "web-tree-sitter";

const RULE_ID = "go-security.rate-limit.self-denial";
const RATE_LIMIT_MEMBER = /^(?:RateLimit|rateLimit|Allow|Wait)$/;
const SELF_HELPER_NAME = /^(?:isAgent|isSelf|isOwnProcess|isCurrentProcess|isServerProcess)$/;
const CONTEXT_PID_MEMBER = /^(?:CallerPID|PIDFromContext|ProcessIDFromContext|CallerProcessID)$/;

interface CallFact {
  receiver: string;
  member: string;
  args: string[];
  start: number;
  end: number;
  line: number;
  endLine: number;
  text: string;
  executable: boolean;
}

interface GuardFact {
  condition: string;
  start: number;
  end: number;
  consequenceStart: number;
  consequenceEnd: number;
  returns: boolean;
  executable: boolean;
  topLevel: boolean;
}

interface ContextBindingFact {
  name: string;
  originEnd: number;
  scopeEnd: number;
}

interface ReturnFact {
  expression: string;
  executable: boolean;
  topLevel: boolean;
}

interface FunctionFact {
  file: SourceRevision;
  packageKey: string;
  familyKey: string;
  name: string;
  receiverName?: string;
  receiverType?: string;
  params: Map<string, string>;
  start: number;
  end: number;
  line: number;
  endLine: number;
  text: string;
  calls: CallFact[];
  guards: GuardFact[];
  returns: ReturnFact[];
  localContexts: ContextBindingFact[];
  imports: Map<string, string>;
}

interface SelfHelper {
  fn: FunctionFact;
}

interface RawFinding {
  fingerprint: string;
  groupFingerprint: string;
  handler: FunctionFact;
  rateCall: CallFact;
  established: SelfHelper;
}

interface ProgramFacts {
  functions: FunctionFact[];
  selfHelpers: SelfHelper[];
}

export async function selfRateLimitDenialSignals(files: SourceRevision[]): Promise<Signal[]> {
  const current = await rawFindings(files);
  const previousFiles = previousRevisions(files);
  const comparePrevious = files.some((file) => file.status === "modified" && file.previous !== undefined);
  const previous = !comparePrevious || previousFiles.length === 0 ? [] : await rawFindings(previousFiles);
  const previousFingerprints = new Set(previous.map((finding) => finding.fingerprint));
  const emittedGroups = new Set<string>();

  return current.flatMap((finding): Signal[] => {
    if (previousFingerprints.has(finding.fingerprint)) return [];
    const anchor = changedAnchor(finding);
    if (anchor === undefined) return [];
    if (emittedGroups.has(finding.groupFingerprint)) return [];
    emittedGroups.add(finding.groupFingerprint);
    return [{
      ruleId: RULE_ID,
      path: anchor.path,
      line: anchor.line,
      ...(anchor.endLine === anchor.line ? {} : { endLine: anchor.endLine }),
      message:
        `${finding.handler.name} adds rate limiting without the service's established self-caller exemption; ` +
        "an operator limit can deny service-owned health or maintenance calls.",
      snippet: anchor.snippet,
      data: {
        handler: finding.handler.name,
        rateLimitCall: finding.rateCall.member,
        establishedSelfCheck: finding.established.fn.name,
        establishedPath: finding.established.fn.file.path,
        semanticFingerprint: finding.fingerprint,
      },
    }];
  });
}

async function rawFindings(files: SourceRevision[]): Promise<RawFinding[]> {
  const goFiles = files.filter((file) =>
    file.path.endsWith(".go") &&
    !file.path.endsWith("_test.go") &&
    !/(?:^|\/)(?:vendor|testdata|generated|mocks?|fakes?)(?:\/|$)/i.test(file.path));
  const program = await collectProgram(goFiles);
  const established = program.selfHelpers.filter((helper) =>
    mentionsHealth(helper.fn.file.current) &&
    program.functions.some((fn) =>
      fn.familyKey === helper.fn.familyKey &&
      fn.packageKey === helper.fn.packageKey &&
      fn.calls.some((call) => isRateLimitCall(call) && guardedBySelfExemption(call, helper, fn))));
  if (established.length === 0) return [];

  const findings: RawFinding[] = [];
  for (const handler of program.functions) {
    if (handler.receiverType === undefined || !isContextBearingHandler(handler)) continue;
    if (/rate.?limit/i.test(handler.name)) continue;
    const familyExemption = established.find((helper) => helper.fn.familyKey === handler.familyKey);
    if (familyExemption === undefined) continue;

    for (const rateCall of handler.calls) {
      if (!rateCall.executable || !isRateLimitCall(rateCall)) continue;
      if (!receiverStartsWith(rateCall.receiver, handler.receiverName)) continue;
      if (!bindingUnshadowed(handler, handler.receiverName, rateCall.start)) continue;
      if (guardedByAnyLocalSelfExemption(rateCall, handler, program.selfHelpers)) continue;
      if (resolvedRateLimitHelperIsSafe(rateCall, handler, program)) continue;

      findings.push({
        fingerprint: [
          handler.familyKey,
          handler.packageKey,
          handler.receiverType,
          handler.name,
          rateCall.member,
        ].join("|"),
        groupFingerprint: [
          handler.familyKey,
          handler.packageKey,
          handler.receiverType,
          rateCall.member,
        ].join("|"),
        handler,
        rateCall,
        established: familyExemption,
      });
    }
  }
  return deduplicate(findings);
}

async function collectProgram(files: SourceRevision[]): Promise<ProgramFacts> {
  const functions: FunctionFact[] = [];
  for (const file of files) {
    const tree = await parseGo(file.current);
    try {
      if (tree.rootNode.hasError) continue;
      const packageNode = tree.rootNode.namedChildren.find((node) => node.type === "package_clause");
      const packageName = packageNode === undefined
        ? ""
        : sourceText(packageNode, file.current).replace(/^package\s+/, "").trim();
      const packageKey = `${dirname(file.path)}:${packageName}`;
      const familyKey = dirname(dirname(file.path));
      const imports = importAliases(tree.rootNode, file.current);

      for (const node of [
        ...descendants(tree.rootNode, "function_declaration"),
        ...descendants(tree.rootNode, "method_declaration"),
      ]) {
        const nameNode = node.childForFieldName("name");
        const body = node.childForFieldName("body");
        if (nameNode === null || body === null) continue;
        const receiver = node.childForFieldName("receiver");
        const receiverInfo = receiver === null ? {} : receiverBinding(receiver, file.current);
        const params = parameterBindings(node.childForFieldName("parameters"), file.current);
        const localContexts = localContextBindings(body, params, file.current);
        const calls = descendants(body, "call_expression").flatMap((call): CallFact[] => {
          if (!directlyOwned(call, body)) return [];
          const callable = call.childForFieldName("function");
          const argumentsNode = call.childForFieldName("arguments");
          if (callable === null || argumentsNode === null) return [];
          let callReceiver = "";
          let member = "";
          if (callable.type === "selector_expression") {
            const operand = callable.childForFieldName("operand");
            const field = callable.childForFieldName("field");
            if (operand === null || field === null) return [];
            callReceiver = sourceText(operand, file.current);
            member = sourceText(field, file.current);
          } else if (callable.type === "identifier") {
            member = sourceText(callable, file.current);
          } else {
            return [];
          }
          return [{
            receiver: callReceiver,
            member,
            args: argumentsNode.namedChildren.map((arg) => sourceText(arg, file.current)),
            start: call.startIndex,
            end: call.endIndex,
            line: call.startPosition.row + 1,
            endLine: call.endPosition.row + 1,
            text: sourceText(call, file.current),
            executable: !staticallyDead(call, file.current),
          }];
        });
        const guards = descendants(body, "if_statement").flatMap((guard): GuardFact[] => {
          if (!directlyOwned(guard, body)) return [];
          const condition = guard.childForFieldName("condition");
          const consequence = guard.childForFieldName("consequence");
          if (condition === null || consequence === null) return [];
          return [{
            condition: compact(sourceText(condition, file.current)),
            start: guard.startIndex,
            end: guard.endIndex,
            consequenceStart: consequence.startIndex,
            consequenceEnd: consequence.endIndex,
            returns: directReturn(consequence, file.current),
            executable: !staticallyDead(guard, file.current),
            topLevel: isTopLevelStatement(guard, body),
          }];
        });
        const returns = descendants(body, "return_statement").flatMap((statement): ReturnFact[] => {
          if (!directlyOwned(statement, body)) return [];
          return [{
            expression: compact(sourceText(statement, file.current)).replace(/^return/, ""),
            executable: !staticallyDead(statement, file.current),
            topLevel: isTopLevelStatement(statement, body),
          }];
        });
        functions.push({
          file,
          packageKey,
          familyKey,
          name: sourceText(nameNode, file.current),
          ...receiverInfo,
          params,
          start: node.startIndex,
          end: node.endIndex,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          text: sourceText(node, file.current),
          calls,
          guards,
          returns,
          localContexts,
          imports,
        });
      }
    } finally {
      tree.delete();
    }
  }

  return {
    functions,
    selfHelpers: functions.flatMap((fn): SelfHelper[] => {
      return isProvenSelfHelper(fn) ? [{ fn }] : [];
    }),
  };
}

function isProvenSelfHelper(fn: FunctionFact): boolean {
  if (!SELF_HELPER_NAME.test(fn.name) || fn.receiverType !== undefined) return false;
  const contextAliases = new Set(
    [...fn.imports].filter(([, path]) => path === "context").map(([alias]) => alias),
  );
  const contextParam = [...fn.params].find(([, type]) =>
    [...contextAliases].some((alias) => compact(type) === `${alias}.Context`));
  if (contextParam === undefined) return false;
  const osAliases = new Set([...fn.imports].filter(([, path]) => path === "os").map(([alias]) => alias));
  const contextPIDCalls = fn.calls.filter((call) =>
    CONTEXT_PID_MEMBER.test(call.member) &&
    call.args.some((arg) => compact(arg) === contextParam[0]) &&
    [...fn.imports].some(([alias, path]) =>
      compact(call.receiver) === alias && /(?:^|\/)(?:rpccontext|peertracker)$/.test(path)));
  const processPIDCalls = fn.calls.filter((call) =>
    call.member === "Getpid" && call.args.length === 0 && osAliases.has(compact(call.receiver)));
  if (contextPIDCalls.length !== 1 || processPIDCalls.length !== 1) return false;
  if (fn.returns.length !== 1) return false;
  if (!bindingUnshadowed(fn, compact(contextPIDCalls[0]!.receiver), contextPIDCalls[0]!.start)) return false;
  if (!bindingUnshadowed(fn, compact(processPIDCalls[0]!.receiver), processPIDCalls[0]!.start)) return false;
  const contextCall = compact(contextPIDCalls[0]!.text);
  const processCall = compact(processPIDCalls[0]!.text);
  const comparesIdentity = fn.returns.some((result) =>
    result.executable && result.topLevel &&
    (result.expression === `${contextCall}==${processCall}` ||
      result.expression === `${processCall}==${contextCall}`));
  return comparesIdentity;
}

function mentionsHealth(source: string): boolean {
  return /(?:health(?:\s|-)?(?:check|probe)|liveness|readiness)/i.test(source);
}

function isRateLimitCall(call: CallFact): boolean {
  if (!RATE_LIMIT_MEMBER.test(call.member)) return false;
  const target = compact(`${call.receiver}.${call.member}`);
  return /rate.?limit/i.test(target) || /(?:limiter|quota)\.(?:Allow|Wait)$/i.test(target);
}

function guardedBySelfExemption(call: CallFact, helper: SelfHelper, fn: FunctionFact): boolean {
  if (helper.fn.packageKey !== fn.packageKey) return false;
  if (fn.guards.some((guard) =>
    guard.executable &&
    bindingUnshadowed(fn, helper.fn.name, guard.start) &&
    guard.consequenceStart <= call.start && guard.consequenceEnd >= call.end &&
    contextBindingsAt(fn, guard.start).some((context) =>
      isNegativeSelfCondition(guard.condition, helper.fn.name, context)))) return true;

  return fn.guards.some((guard) =>
    guard.executable && guard.topLevel && guard.end < call.start && guard.returns &&
    bindingUnshadowed(fn, helper.fn.name, guard.start) &&
    contextBindingsAt(fn, guard.start).some((context) =>
      isPositiveSelfCondition(guard.condition, helper.fn.name, context)));
}

function guardedByAnyLocalSelfExemption(
  call: CallFact,
  fn: FunctionFact,
  helpers: SelfHelper[],
): boolean {
  return helpers.some((helper) => helper.fn.packageKey === fn.packageKey && guardedBySelfExemption(call, helper, fn));
}

function resolvedRateLimitHelperIsSafe(call: CallFact, handler: FunctionFact, program: ProgramFacts): boolean {
  const helper = program.functions.find((candidate) =>
    candidate.packageKey === handler.packageKey &&
    candidate.receiverType === handler.receiverType &&
    candidate.name === call.member);
  if (helper === undefined) return false;
  const helperRateCall = helper.calls.find((candidate) => candidate.executable && isRateLimitCall(candidate));
  if (helperRateCall === undefined) return false;
  return program.selfHelpers.some((self) =>
    self.fn.packageKey === helper.packageKey && guardedBySelfExemption(helperRateCall, self, helper));
}

function isContextBearingHandler(fn: FunctionFact): boolean {
  if (contextParameterNames(fn).length > 0 || fn.localContexts.length > 0) return true;
  return fn.calls.some((call) => call.member === "Context" && call.args.length === 0);
}

function contextParameterNames(fn: FunctionFact): string[] {
  const contextAliases = new Set(
    [...fn.imports].filter(([, path]) => path === "context").map(([alias]) => alias),
  );
  return [...fn.params].flatMap(([name, type]) =>
    [...contextAliases].some((alias) => compact(type) === `${alias}.Context`) ? [name] : []);
}

function contextBindingsAt(fn: FunctionFact, before: number): string[] {
  const parameters = contextParameterNames(fn).filter((name) =>
    bindingPreserved(fn, name, fn.start, before));
  const locals = fn.localContexts.flatMap((binding) =>
    binding.originEnd < before && before < binding.scopeEnd &&
    bindingPreserved(fn, binding.name, binding.originEnd, before)
      ? [binding.name]
      : []);
  return [...new Set([...parameters, ...locals])];
}

function changedAnchor(finding: RawFinding): {
  path: string;
  line: number;
  endLine: number;
  snippet: string;
} | undefined {
  const file = finding.handler.file;
  if (file.status === "repository" || file.status === "added") {
    return {
      path: file.path,
      line: finding.rateCall.line,
      endLine: finding.rateCall.endLine,
      snippet: finding.rateCall.text.trim().slice(0, 300),
    };
  }
  for (let line = finding.rateCall.line; line <= finding.rateCall.endLine; line += 1) {
    if (file.changedLines.has(line)) {
      return { path: file.path, line, endLine: line, snippet: finding.rateCall.text.trim().slice(0, 300) };
    }
  }
  return undefined;
}

function previousRevisions(files: SourceRevision[]): SourceRevision[] {
  return files.flatMap((file): SourceRevision[] => {
    if (file.status === "added") return [];
    const { previous, ...revision } = file;
    if (file.status === "context") {
      return [{ ...revision, status: "context", changedLines: new Set() }];
    }
    if (file.status === "modified") {
      if (previous === undefined) return [];
      return [{ ...revision, current: previous, status: "repository", changedLines: new Set() }];
    }
    return [{ ...revision, status: "repository", changedLines: new Set() }];
  });
}

function importAliases(root: Node, source: string): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const spec of descendants(root, "import_spec")) {
    const pathNode = spec.childForFieldName("path");
    if (pathNode === null) continue;
    const path = sourceText(pathNode, source).replace(/^"|"$/g, "");
    const nameNode = spec.childForFieldName("name");
    const alias = nameNode === null ? (path.split("/").pop() ?? "") : sourceText(nameNode, source);
    if (alias !== "_" && alias !== ".") aliases.set(alias, path);
  }
  return aliases;
}

function receiverBinding(node: Node, source: string): { receiverName?: string; receiverType?: string } {
  const text = sourceText(node, source).replace(/^\(|\)$/g, "").trim();
  const match = text.match(/^([A-Za-z_]\w*)\s+\*?([A-Za-z_]\w*)$/);
  const receiverName = match?.[1];
  const receiverType = match?.[2];
  return receiverName === undefined || receiverType === undefined ? {} : { receiverName, receiverType };
}

function parameterBindings(node: Node | null, source: string): Map<string, string> {
  const result = new Map<string, string>();
  if (node === null) return result;
  for (const declaration of descendants(node, "parameter_declaration")) {
    const typeNode = declaration.childForFieldName("type");
    if (typeNode === null) continue;
    const type = sourceText(typeNode, source);
    for (const nameNode of declaration.namedChildren.filter((child) => child.type === "identifier")) {
      result.set(sourceText(nameNode, source), type);
    }
  }
  return result;
}

function localContextBindings(
  body: Node,
  params: Map<string, string>,
  source: string,
): ContextBindingFact[] {
  return descendants(body, "short_var_declaration").flatMap((declaration): ContextBindingFact[] => {
    const statements = declaration.parent;
    if (statements?.type !== "statement_list" || statements.parent?.id !== body.id) return [];
    const match = compact(sourceText(declaration, source)).match(
      /^([A-Za-z_]\w*):=([A-Za-z_]\w*)\.Context\(\)$/,
    );
    if (match?.[1] === undefined || match[2] === undefined || !params.has(match[2])) return [];
    return [{ name: match[1], originEnd: declaration.endIndex, scopeEnd: body.endIndex }];
  });
}

function staticallyDead(node: Node, source: string): boolean {
  let current: Node | null = node;
  while (current?.parent !== null && current?.parent !== undefined) {
    const parent: Node = current.parent;
    if (parent.type === "statement_list") {
      const statement = parent.namedChildren.find((child) => contains(child, node));
      if (statement !== undefined) {
        const index = parent.namedChildren.indexOf(statement);
        if (parent.namedChildren.slice(0, index).some((sibling) => sibling.type === "return_statement")) return true;
      }
    }
    if (parent.type === "if_statement") {
      const condition = parent.childForFieldName("condition");
      const consequence = parent.childForFieldName("consequence");
      const alternative = parent.childForFieldName("alternative");
      const value = condition === null ? "" : compact(sourceText(condition, source));
      if (value === "false" && consequence !== null && contains(consequence, node)) return true;
      if (value === "true" && alternative !== null && contains(alternative, node)) return true;
    }
    current = parent;
    if (parent.type === "function_declaration" || parent.type === "method_declaration") break;
  }
  return false;
}

function directlyOwned(node: Node, body: Node): boolean {
  let current: Node | null = node;
  while (current !== null && current.id !== body.id) {
    if (current.type === "func_literal") return false;
    current = current.parent;
  }
  return current !== null;
}

function directReturn(block: Node, source: string): boolean {
  const statements = block.namedChildren.find((node) => node.type === "statement_list");
  return statements?.namedChildren.some((node) =>
    node.type === "return_statement" && /^return(?:nil)?$/.test(compact(sourceText(node, source)))) ?? false;
}

function isTopLevelStatement(node: Node, body: Node): boolean {
  const statements = node.parent;
  return statements?.type === "statement_list" && statements.parent?.id === body.id;
}

function isNegativeSelfCondition(text: string, helper: string, context: string): boolean {
  return text === `!${helper}(${context})` || text === `${helper}(${context})==false` || text === `false==${helper}(${context})`;
}

function isPositiveSelfCondition(text: string, helper: string, context: string): boolean {
  return text === `${helper}(${context})` || text === `${helper}(${context})==true` || text === `true==${helper}(${context})`;
}

function receiverStartsWith(receiver: string, name: string | undefined): boolean {
  if (name === undefined) return false;
  const value = compact(receiver);
  return value === name || value.startsWith(`${name}.`);
}

function bindingUnshadowed(fn: FunctionFact, name: string | undefined, before: number): boolean {
  if (name === undefined) return false;
  if (fn.params.has(name)) return false;
  const prefix = fn.file.current.slice(fn.start, before);
  return !bindingWritePattern(name).test(prefix);
}

function bindingPreserved(fn: FunctionFact, name: string, after: number, before: number): boolean {
  return !bindingWritePattern(name).test(fn.file.current.slice(after, before));
}

function bindingWritePattern(name: string): RegExp {
  const escaped = escapeRegExp(name);
  return new RegExp(`(?:^|[;{}\\n])\\s*(?:var\\s+${escaped}\\b|${escaped}\\s*(?::=|=(?!=)))`);
}

function contains(outer: Node, inner: Node): boolean {
  return outer.startIndex <= inner.startIndex && outer.endIndex >= inner.endIndex;
}

function compact(value: string): string {
  return value.replace(/\s+/g, "").replace(/^\((.*)\)$/s, "$1");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function deduplicate(findings: RawFinding[]): RawFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.fingerprint)) return false;
    seen.add(finding.fingerprint);
    return true;
  });
}
