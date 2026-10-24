"""Static Python analysis. Uploaded source is never imported or executed."""
import ast
import io
import posixpath
import stat
import tokenize
import zipfile
from pathlib import PurePosixPath
from intelligence import scan_security, symbol_metadata

MAX_UPLOAD = 10 * 1024 * 1024
MAX_TOTAL = 20 * 1024 * 1024
MAX_FILE = 512 * 1024
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages"}

class AnalysisError(ValueError):
    pass

def read_archive(data):
    if len(data) > MAX_UPLOAD:
        raise AnalysisError("ZIP exceeds the 10 MB upload limit.")
    sources = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 2000:
                raise AnalysisError("ZIP contains more than 2,000 entries.")
            total, seen = 0, set()
            for entry in entries:
                name = entry.orig_filename
                path = PurePosixPath(name)
                if "\\" in name or name.startswith("/") or ":" in name or ".." in path.parts:
                    raise AnalysisError("ZIP contains an unsafe file path.")
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise AnalysisError("ZIP contains a symbolic link.")
                if name in seen:
                    raise AnalysisError("ZIP contains duplicate file paths.")
                seen.add(name)
                if entry.flag_bits & 1:
                    raise AnalysisError("Encrypted ZIP files are not supported.")
                total += entry.file_size
                if total > MAX_TOTAL:
                    raise AnalysisError("Uncompressed archive exceeds 20 MB.")
                if entry.is_dir() or any(part in SKIP for part in path.parts) or path.suffix != ".py":
                    continue
                if entry.file_size > MAX_FILE:
                    raise AnalysisError(f"Python file exceeds 512 KB: {name}")
                if entry.file_size > 100_000 and entry.file_size / max(entry.compress_size, 1) > 200:
                    raise AnalysisError("Suspicious archive compression ratio.")
                if len(sources) >= 300:
                    raise AnalysisError("Repository exceeds 300 Python files.")
                with archive.open(entry) as stream:
                    raw = stream.read(MAX_FILE + 1)
                if len(raw) > MAX_FILE:
                    raise AnalysisError("Python file exceeds 512 KB.")
                try:
                    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                    sources[name] = raw.decode(encoding)
                except (UnicodeError, SyntaxError, LookupError):
                    sources[name] = None
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError) as exc:
        raise AnalysisError("Invalid or unsupported ZIP archive.") from exc
    if not sources:
        raise AnalysisError("No Python source files found in the ZIP.")
    while all("/" in name for name in sources):
        roots = {name.split("/")[0] for name in sources}
        if len(roots) != 1 or any(name.count("/") == 1 and name.endswith("/__init__.py") for name in sources):
            break
        sources = {name.split("/", 1)[1]: source for name, source in sources.items()}
    return sources

def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""

def literal(node, default=None):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        return [literal(item) for item in node.elts]
    return default

def keywords(call):
    return {kw.arg: kw.value for kw in call.keywords if kw.arg}

def module_name(path):
    name = path.removesuffix(".py").replace("/", ".")
    return name.removesuffix(".__init__") if name != "__init__" else "__init__"

def analyze(data, name="repository"):
    sources = read_archive(data)
    modules, symbols, routes, findings, edges, security_findings = [], [], [], [], [], []
    trees, aliases, imports, import_lines, owners, mounts = {}, {}, {}, {}, {}, []
    names = {module_name(path): path for path in sources}
    if len(names) != len(sources):
        raise AnalysisError("Ambiguous module names: package and module share a name.")
    def finding(kind, message, file, line=1):
        findings.append({"kind": kind, "message": message, "file": file, "line": line})
    for path, source in sorted(sources.items()):
        mod = module_name(path)
        modules.append({"id": mod, "name": mod, "file": path, "lines": len((source or "").splitlines()), "docstring": "", "source": source or ""})
        if source is None:
            finding("encoding", "Unable to decode Python source.", path)
            continue
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            finding("syntax", str(exc)[:250], path, getattr(exc, "lineno", 1) or 1)
            continue
        if sum(1 for _ in ast.walk(tree)) > 50000:
            finding("limit", "File skipped: too many syntax nodes.", path)
            continue
        trees[mod] = tree
        modules[-1]["docstring"] = ast.get_docstring(tree) or ""
        if not modules[-1]["docstring"]:
            finding("missing_docstring", "Module has no docstring.", path)
        aliases[mod], imports[mod], import_lines[mod] = {}, [], {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[mod][alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
                    imports[mod].append(alias.name)
                    import_lines[mod].setdefault(alias.name, node.lineno)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    package = mod.split(".") if path.endswith("__init__.py") else mod.split(".")[:-1]
                    base = ".".join(package[:len(package) - node.level + 1]) if node.level <= len(package) else ""
                    base = ".".join(filter(None, [base, node.module]))
                else:
                    base = node.module or ""
                imports[mod].append(base)
                import_lines[mod].setdefault(base, node.lineno)
                for alias in node.names:
                    full = ".".join(filter(None, [base, alias.name]))
                    aliases[mod][alias.asname or alias.name] = full
                    imports[mod].append(full)
                    import_lines[mod].setdefault(full, node.lineno)
        module_imports = [{"name": item, "line": import_lines[mod].get(item, 1)} for item in dict.fromkeys(imports[mod])]
        security_findings.extend({**item, "file": path} for item in scan_security(tree, source, aliases[mod]))
        def resolve(value):
            head, _, rest = value.partition(".")
            return aliases[mod].get(head, head) + ("." + rest if rest else "")
        for node in tree.body:
            value = getattr(node, "value", None)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(value, ast.Call):
                constructor = resolve(dotted(value.func))
                if constructor in {"fastapi.FastAPI", "fastapi.APIRouter"}:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    opts = keywords(value)
                    prefix = literal(opts["prefix"]) if "prefix" in opts else ""
                    for target in targets:
                        if isinstance(target, ast.Name):
                            owners[f"{mod}.{target.id}"] = {"type": constructor.split(".")[-1], "prefix": prefix if isinstance(prefix, str) else "", "module": mod}
                            if "prefix" in opts and not isinstance(literal(opts["prefix"]), str):
                                finding("dynamic_route", "Router prefix is dynamic; path may be incomplete.", path, node.lineno)
        def walk_defs(body, parent=""):
            for node in body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                qualified = f"{parent}.{node.name}" if parent else node.name
                ident = f"{mod}:{qualified}"
                doc = ast.get_docstring(node) or ""
                signature = node.name if isinstance(node, ast.ClassDef) else f"{node.name}({ast.unparse(node.args)})" + (f" -> {ast.unparse(node.returns)}" if node.returns else "")
                symbols.append({"id": ident, "name": qualified, "module": mod, "kind": "class" if isinstance(node, ast.ClassDef) else "function", "signature": signature, "docstring": doc, "file": path, "line": node.lineno, **symbol_metadata(node, module_imports)})
                if not doc:
                    finding("missing_docstring", f"{qualified} has no docstring.", path, node.lineno)
                if not isinstance(node, ast.ClassDef):
                    for deco in node.decorator_list:
                        if not isinstance(deco, ast.Call) or not isinstance(deco.func, ast.Attribute):
                            continue
                        method = deco.func.attr
                        if method not in {"get", "post", "put", "patch", "delete", "options", "head", "api_route", "websocket"}:
                            continue
                        owner = f"{mod}.{dotted(deco.func.value)}"
                        if owner not in owners:
                            continue
                        opts = keywords(deco)
                        route_path = literal(deco.args[0] if deco.args else opts.get("path"))
                        if not isinstance(route_path, str):
                            finding("dynamic_route", f"Dynamic path for {qualified} cannot be resolved.", path, node.lineno)
                            continue
                        methods = (literal(opts["methods"]) if "methods" in opts else ["GET"]) if method == "api_route" else [method.upper()]
                        if not isinstance(methods, list) or not all(isinstance(item, str) for item in methods):
                            finding("dynamic_route", f"Dynamic methods for {qualified} cannot be resolved.", path, node.lineno)
                            continue
                        for verb in methods:
                            routes.append({"method": verb.upper(), "path": route_path, "owner": owner, "symbol": ident, "handler": qualified, "file": path, "line": node.lineno, "signature": signature, "docstring": doc, "response_model": ast.unparse(opts["response_model"]) if "response_model" in opts else "", "status_code": ast.unparse(opts["status_code"]) if "status_code" in opts else "200", "mounted": False})
                walk_defs(node.body, qualified)
        walk_defs(tree.body)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router":
                opts = keywords(node)
                router = node.args[0] if node.args else opts.get("router")
                target = resolve(dotted(router))
                if "." not in target:
                    target = f"{mod}.{target}"
                parent = f"{mod}.{dotted(node.func.value)}"
                prefix = literal(opts["prefix"]) if "prefix" in opts else ""
                if not isinstance(prefix, str):
                    finding("dynamic_route", "Dynamic include_router prefix cannot be resolved.", path, node.lineno)
                    continue
                mounts.append((parent, target, prefix))
    edge_set, edge_by_key = set(), {}
    def add_edge(source, target, kind, file=None, line=None):
        key = (source, target, kind)
        if source == target:
            return
        if key not in edge_set:
            edge_set.add(key)
            edge = {"source": source, "target": target, "kind": kind, "file": file, "line": line, "locations": []}
            edge_by_key[key] = edge
            edges.append(edge)
        edge = edge_by_key[key]
        if file and line:
            location = {"file": file, "line": line}
            if location not in edge["locations"]:
                edge["locations"].append(location)
            if edge["line"] is None:
                edge["file"], edge["line"] = file, line
    for mod, targets in imports.items():
        for target in targets:
            parts = target.split(".")
            while parts and ".".join(parts) not in names:
                parts.pop()
            if parts:
                add_edge(mod, ".".join(parts), "import", names[mod], import_lines[mod].get(target))
    symbol_ids = {s["id"] for s in symbols}
    for symbol in symbols:
        tree = trees[symbol["module"]]
        node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.lineno == symbol["line"])
        if isinstance(node, ast.ClassDef):
            continue
        pending = list(ast.iter_child_nodes(node))
        while pending:
            child = pending.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            pending.extend(ast.iter_child_nodes(child))
            if not isinstance(child, ast.Call):
                continue
            call = dotted(child.func)
            local = f'{symbol["module"]}:{call}'
            if local in symbol_ids:
                add_edge(symbol["id"], local, "call", names[symbol["module"]], child.lineno)
                continue
            head, _, tail = call.partition(".")
            resolved = aliases[symbol["module"]].get(head, head) + ("." + tail if tail else "")
            for module in sorted(names, key=len, reverse=True):
                if resolved.startswith(module + "."):
                    candidate = module + ":" + resolved[len(module) + 1:]
                    if candidate in symbol_ids:
                        add_edge(symbol["id"], candidate, "call", names[symbol["module"]], child.lineno)
                    break
    graph = {name: [] for name in names}
    for edge in edges:
        if edge["kind"] == "import":
            graph[edge["source"]].append(edge["target"])
    index, low, stack, active, cycles = {}, {}, [], set(), []
    def visit(v):
        index[v] = low[v] = len(index)
        stack.append(v); active.add(v)
        for w in graph[v]:
            if w not in index:
                visit(w); low[v] = min(low[v], low[w])
            elif w in active:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component = []
            while True:
                w = stack.pop(); active.remove(w); component.append(w)
                if w == v:
                    break
            if len(component) > 1:
                cycles.append(sorted(component))
    for mod in graph:
        if mod not in index:
            visit(mod)
    for cycle in cycles:
        finding("import_cycle", "Circular import group: " + ", ".join(cycle), names[cycle[0]])
    def prefixes(owner, seen=None):
        seen = set() if seen is None else seen
        if owner in seen or owner not in owners:
            return []
        current = owners[owner]
        if current["type"] == "FastAPI":
            return [current["prefix"]]
        result = []
        for parent, child, prefix in mounts:
            if child == owner:
                result.extend(p + prefix + current["prefix"] for p in prefixes(parent, seen | {owner}))
        return result
    expanded = []
    for route in routes:
        roots = prefixes(route["owner"])
        for prefix in roots or [owners[route["owner"]]["prefix"]]:
            expanded.append({**route, "path": prefix + route["path"], "mounted": bool(roots)})
    missing = sum(f["kind"] == "missing_docstring" for f in findings)
    total = len(modules) + len(symbols)
    result = {"name": posixpath.basename(name).removesuffix(".zip")[:100], "modules": modules, "symbols": symbols, "edges": edges, "routes": expanded, "findings": findings, "security_findings": security_findings, "cycles": cycles,
              "stats": {"modules": len(modules), "symbols": len(symbols), "routes": len(expanded), "lines": sum(m["lines"] for m in modules), "coverage": round(100 * sum(bool(x["docstring"]) for x in modules + symbols) / max(total, 1)), "missing_docstrings": missing},
              "limitations": ["Static AST analysis only; source is never executed.", "Dynamic imports, runtime route registration, re-exports, object-method dispatch, and conditional execution are not fully resolved.", "Router mounting is resolved for direct imports and literal prefixes; unmounted routers are labeled.", "Documentation describes source declarations; it is not a complete OpenAPI schema.", "Security findings are conservative static patterns, not proof of exploitability or absence of vulnerabilities."]}
    result["markdown"] = markdown(result)
    return result

def markdown(result):
    def safe(value):
        import html
        return html.escape(str(value)).replace(chr(96), "&#96;")
    out = [f'# {safe(result["name"])} — API documentation', "", "> Generated by AutoDoc AI using static Python AST analysis.", "", "## Summary", ""]
    out += [f'- {key.replace("_", " ").title()}: {value}' for key, value in result["stats"].items()]
    out += ["", "## API routes", ""]
    for route in result["routes"]:
        out += [f'### {route["method"]} {safe(route["path"])}', "", f'Handler: {safe(route["signature"])}', "", f'Source: {safe(route["file"])}:{route["line"]}', "", f'Response model: {safe(route["response_model"] or "Not declared")} · Status: {safe(route["status_code"])}', "", "Mounted: " + ("yes" if route["mounted"] else "not resolved"), "", safe(route["docstring"] or "No docstring provided."), ""]
    if not result["routes"]:
        out += ["No statically recognized FastAPI routes.", ""]
    out += ["## Modules and symbols", ""]
    for module in result["modules"]:
        out += [f'### {safe(module["name"])}', "", safe(module["docstring"] or "No module docstring."), ""]
        for symbol in result["symbols"]:
            if symbol["module"] == module["id"]:
                out += [f'#### {safe(symbol["signature"])}', "", f'{safe(symbol["file"])}:{symbol["line"]}', "", safe(symbol["docstring"] or "No docstring provided."), ""]
    out += ["## Quality findings", ""]
    out += [f'- {safe(f["file"])}:{f["line"]} — {safe(f["message"])}' for f in result["findings"]] or ["No findings."]
    out += ["", "## Security patterns (static heuristics)", ""]
    security = result.get("security_findings", [])
    for item in security:
        out += [f'### {safe(item["severity"])} · {safe(item["rule_id"])} — {safe(item["title"])}', "", f'Source: {safe(item["file"])}:{item["line"]} · Confidence: {safe(item["confidence"])}', "", safe(item["risk"]), "", f'Suggested remediation: {safe(item["remediation"])}', "", f'```python\n{safe(item["snippet"])}\n```', ""]
    if not security:
        out += ["No configured patterns detected. This does not establish that the repository is secure.", ""]
    out += ["", "## Analysis boundaries", ""] + ["- " + item for item in result["limitations"]]
    return "\n".join(out) + "\n"

