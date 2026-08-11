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
