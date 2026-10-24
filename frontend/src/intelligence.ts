export type SymbolFact = {
  id: string; name: string; module: string; kind: string; signature: string;
  docstring: string; file: string; line: number;
  parameters?: { name: string; kind: string; annotation: string; default: string | null }[];
  return_annotation?: string; return_expressions?: { line: number; expression: string }[];
  decorators?: string[]; bases?: string[];
  imports?: { name: string; line: number }[];
};
export type EdgeFact = {
  source: string; target: string; kind: string; file?: string | null; line?: number | null;
  locations?: { file: string; line: number }[];
};
export type ModuleFact = { id: string; name: string; file: string; lines: number; docstring: string };
export type AnalysisFacts = { symbols: SymbolFact[]; modules: ModuleFact[]; edges: EdgeFact[] };
export type ImpactRelation = {
  id: string; label: string; file: string; line: number; kind: string;
  direction: string; reason: string; depth: number;
};
export type AffectedModule = { id: string; name: string; file: string; depth: number; reason: string };
export type ImpactReport = {
  target: SymbolFact; direct: ImpactRelation[]; transitive: ImpactRelation[];
  modules: AffectedModule[]; edgeKeys: string[];
};

export const edgeKey = (edge: Pick<EdgeFact, 'source'|'target'|'kind'>) => `${edge.source}|${edge.target}|${edge.kind}`;

/**
 * Impact is a static graph traversal. Only call edges are treated as call relationships;
 * module imports and containment are labeled separately as indirect evidence.
 */
export function buildImpactReport(targetId: string, facts: AnalysisFacts): ImpactReport {
  const target = facts.symbols.find(symbol => symbol.id === targetId);
  if (!target) throw new Error('Select a function or class before analyzing impact.');
  const byId = new Map(facts.symbols.map(symbol => [symbol.id, symbol]));
  const moduleById = new Map(facts.modules.map(module => [module.id, module]));
  const calls = facts.edges.filter(edge => edge.kind === 'call');
  const callersByCallee = new Map<string, EdgeFact[]>();
  const calleesByCaller = new Map<string, EdgeFact[]>();
  for (const edge of calls) {
    const callers = callersByCallee.get(edge.target);
    if (callers) callers.push(edge); else callersByCallee.set(edge.target, [edge]);
    const callees = calleesByCaller.get(edge.source);
    if (callees) callees.push(edge); else calleesByCaller.set(edge.source, [edge]);
  }
  const direct: ImpactRelation[] = [];
  const edgeKeys = new Set<string>();
  const directCallers = new Set<string>();
  const addRelation = (edge: EdgeFact, id: string, direction: string, reason: string, depth: number, label?: string) => {
    const symbol = byId.get(id), mod = moduleById.get(id);
    direct.push({
      id, label: label || symbol?.signature || mod?.name || id,
      file: edge.file || symbol?.file || mod?.file || '',
      line: edge.line || symbol?.line || 0,
      kind: edge.kind, direction, reason, depth,
    });
    edgeKeys.add(edgeKey(edge));
  };
  for (const edge of callersByCallee.get(targetId) || []) {
    directCallers.add(edge.source);
    addRelation(edge, edge.source, 'caller', 'This symbol directly calls the selected symbol, so it may be affected by a change to its behavior or signature.', 1);
  }
  for (const edge of calleesByCaller.get(targetId) || []) {
    addRelation(edge, edge.target, 'dependency', 'The selected symbol directly calls this dependency. This is a dependency of the selection, not a reverse caller.', 1);
  }

  const transitive: ImpactRelation[] = [];
  const visited = new Set<string>([targetId, ...directCallers]);
  let frontier = [...directCallers];
  let depth = 1;
  while (frontier.length) {
    const next: string[] = [];
    for (const current of frontier) {
      for (const edge of callersByCallee.get(current) || []) {
        if (visited.has(edge.source)) continue;
        visited.add(edge.source);
        next.push(edge.source);
        edgeKeys.add(edgeKey(edge));
        const symbol = byId.get(edge.source);
        if (symbol) transitive.push({
          id: symbol.id, label: symbol.signature, file: edge.file || symbol.file,
          line: edge.line || symbol.line, kind: edge.kind, direction: 'transitive caller', depth: depth + 1,
          reason: `A caller depends on an intermediate caller ${byId.get(current)?.name || current}; impact is inferred through detected call edges.`,
        });
      }
    }
    frontier = next;
    depth += 1;
  }

  const moduleImports: ImpactRelation[] = [];
  for (const edge of facts.edges) {
    if (edge.kind !== 'import' || edge.target !== target.module || edge.source === target.module) continue;
    const mod = moduleById.get(edge.source);
    if (!mod) continue;
    moduleImports.push({
      id: mod.id, label: mod.name, file: edge.file || mod.file, line: edge.line || 0,
      kind: 'import', direction: 'module import', depth: 1,
      reason: 'This module imports the module containing the selected symbol. An import does not prove that it calls or uses this symbol.',
    });
    edgeKeys.add(edgeKey(edge));
  }
  direct.push(...moduleImports);

  const affectedDepth = new Map<string, number>();
  for (const relation of [...direct, ...transitive]) {
    const symbol = byId.get(relation.id);
    const moduleId = symbol?.module || (relation.kind === 'import' ? relation.id : '');
    if (!moduleId || moduleId === target.module) continue;
    const prior = affectedDepth.get(moduleId);
    if (prior === undefined || relation.depth < prior) affectedDepth.set(moduleId, relation.depth);
  }
  const modules: AffectedModule[] = [...affectedDepth.entries()].flatMap(([id, moduleDepth]) => {
    const mod = moduleById.get(id);
    return mod ? [{
      id, name: mod.name, file: mod.file, depth: moduleDepth,
      reason: moduleDepth === 1 ? 'Contains a direct caller or imports the changed symbol’s module.' : 'Contains a caller reached through one or more intermediate call edges.',
    }] : [];
  }).sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name));

  return { target, direct, transitive, modules, edgeKeys: [...edgeKeys] };
}

/** A deterministic explanation assembled from declarations and graph facts only. */
export function explainSymbol(symbol: SymbolFact, facts: AnalysisFacts): string {
  const lines = [`${symbol.kind === 'class' ? 'Class' : 'Function'}: ${symbol.signature}`, `Source: ${symbol.file}:${symbol.line}`];
  if (symbol.docstring) lines.push('', `Existing docstring: ${symbol.docstring}`);
  else lines.push('', 'Purpose evidence: No docstring is present. The analyzer reports syntax and relationships only; it cannot establish the complete runtime intent.');

  if (symbol.kind === 'class') {
    lines.push(`Bases: ${symbol.bases?.length ? symbol.bases.join(', ') : 'none declared'}`);
    const methods = facts.symbols.filter(item => item.module === symbol.module && item.name.startsWith(symbol.name + '.'));
    lines.push(`Declared methods: ${methods.length ? methods.map(item => item.name.slice(symbol.name.length + 1)).join(', ') : 'none discovered'}`);
  } else {
    lines.push('', 'Parameters:');
    lines.push(...(symbol.parameters?.length ? symbol.parameters.map(parameter => {
      const annotation = parameter.annotation ? `: ${parameter.annotation}` : '';
      const defaultValue = parameter.default !== null && parameter.default !== undefined ? ` = ${parameter.default}` : '';
      return `• ${parameter.name}${annotation}${defaultValue} (${parameter.kind.replaceAll('_', ' ')})`;
    }) : ['• none']));
    if (symbol.return_annotation) lines.push(`Return annotation: ${symbol.return_annotation}`);
    const returnExpressions = symbol.return_expressions || [];
    if (returnExpressions.length) lines.push('Return expressions: ' + returnExpressions.map(item => `line ${item.line}: ${item.expression}`).join('; '));
    else if (!symbol.return_annotation) lines.push('Return value: no explicit return expression or annotation detected.');
  }

  if (symbol.decorators?.length) lines.push(`Decorators: ${symbol.decorators.map(value => '@' + value).join(', ')}`);
  if (symbol.imports?.length) lines.push(`Module imports: ${symbol.imports.map(item => `${item.name} (line ${item.line})`).join(', ')}`);
  const incoming = facts.edges.filter(edge => edge.kind === 'call' && edge.target === symbol.id).map(edge => facts.symbols.find(item => item.id === edge.source)?.signature || edge.source);
  const outgoing = facts.edges.filter(edge => edge.kind === 'call' && edge.source === symbol.id).map(edge => facts.symbols.find(item => item.id === edge.target)?.signature || edge.target);
  lines.push('', 'Detected direct relationships:');
  lines.push(`Called by: ${incoming.length ? incoming.join(', ') : 'none detected'}`);
  lines.push(`Calls: ${outgoing.length ? outgoing.join(', ') : 'none detected'}`);
  if (!symbol.docstring.trim() || symbol.docstring.trim().length < 50) lines.push('', 'Documentation suggestion: Add a concise purpose statement; describe important parameters and return behavior.');
  else lines.push('', 'Documentation suggestion: Verify the docstring still describes current behavior and documents important edge cases.');
  lines.push('', 'This explanation uses static syntax facts only. It does not execute source or infer hidden runtime behavior.');
  return lines.join('\n');
}
