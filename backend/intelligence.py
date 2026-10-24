import ast
import re


def symbol_metadata(node, module_imports):
    """Expose declarations from syntax alone; no object is imported or evaluated."""
    is_function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    args = node.args if is_function else None
    parameters = []
    if args:
        positional = list(args.posonlyargs) + list(args.args)
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        for index, (arg, default) in enumerate(zip(positional, defaults)):
            parameters.append({
                "name": arg.arg,
                "kind": "positional_only" if index < len(args.posonlyargs) else "positional_or_keyword",
                "annotation": ast.unparse(arg.annotation) if arg.annotation else "",
                "default": ast.unparse(default) if default is not None else None,
            })
        if args.vararg:
            parameters.append({"name": args.vararg.arg, "kind": "var_positional", "annotation": ast.unparse(args.vararg.annotation) if args.vararg.annotation else "", "default": None})
        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            parameters.append({"name": arg.arg, "kind": "keyword_only", "annotation": ast.unparse(arg.annotation) if arg.annotation else "", "default": ast.unparse(default) if default is not None else None})
        if args.kwarg:
            parameters.append({"name": args.kwarg.arg, "kind": "var_keyword", "annotation": ast.unparse(args.kwarg.annotation) if args.kwarg.annotation else "", "default": None})

    returns = []
    if is_function:
        class ReturnVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, child):
                if child is node:
                    for statement in child.body:
                        self.visit(statement)
            visit_AsyncFunctionDef = visit_FunctionDef
            def visit_Lambda(self, child):
                return
            def visit_ClassDef(self, child):
                return
            def visit_Return(self, child):
                if child.value is not None and len(returns) < 8:
                    returns.append({"line": child.lineno, "expression": ast.unparse(child.value)[:240]})
        ReturnVisitor().visit(node)

    return {
        "parameters": parameters,
        "return_annotation": ast.unparse(node.returns) if is_function and node.returns else "",
        "return_expressions": returns,
        "decorators": [ast.unparse(decorator)[:200] for decorator in node.decorator_list],
        "bases": [ast.unparse(base)[:160] for base in node.bases] if isinstance(node, ast.ClassDef) else [],
        "imports": module_imports[:30],
    }


def _redact(source_line):
    pattern = re.compile(r"(?i)(\b[A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|credential|private[_-]?key)[A-Za-z0-9_]*\b\s*[:=]\s*).*$")
    safe = pattern.sub(lambda match: match.group(1) + "'[REDACTED]'", source_line.strip())
    safe = re.sub(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED_TOKEN]", safe)
    return safe[:240]


def scan_security(tree, source, aliases):
    """Return conservative, source-linked patterns; these are not vulnerability proofs."""
    findings = []
    source_lines = source.splitlines()

    def emit(rule_id, title, severity, confidence, node, risk, remediation, safe_snippet=None):
        line = max(1, getattr(node, "lineno", 1))
        snippet = source_lines[line - 1] if line <= len(source_lines) else ""
        findings.append({
            "rule_id": rule_id, "title": title, "severity": severity,
            "confidence": confidence, "line": line, "snippet": safe_snippet if safe_snippet is not None else _redact(snippet),
            "risk": risk, "remediation": remediation,
        })

    def target_names(target):
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for child in target.elts for name in target_names(child)]
        return []

    credential_name = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|credential|private[_-]?key)")
    placeholders = ("password", "secret", "changeme", "change_me", "your_", "example", "sample", "dummy", "placeholder", "none", "null", "test", "replace", "demo-only")

    for node in ast.walk(tree):
        targets, assigned = [], None
        if isinstance(node, ast.Assign):
            targets = [name for target in node.targets for name in target_names(target)]
            assigned = node.value
        elif isinstance(node, ast.AnnAssign):
            targets, assigned = target_names(node.target), node.value

        if assigned is not None and isinstance(assigned, ast.Constant) and isinstance(assigned.value, str):
            value = assigned.value.strip()
            if len(value) >= 8 and not any(marker in value.lower() for marker in placeholders) and any(credential_name.search(name) for name in targets):
                safe_names = [name for name in targets if credential_name.search(name)]
                safe_snippet = "; ".join(f"{name} = '[REDACTED]'" for name in safe_names)
                emit("PYSEC001", "Possible hardcoded credential", "High" if len(value) >= 16 else "Medium", "medium", node,
                     "A credential-like variable is assigned a non-placeholder string literal. If it is real, it could be exposed through source control or a package.",
                     "Move the value to an environment variable or secret manager, rotate any committed secret, and avoid logging it.", safe_snippet)

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            lhs = node.targets if isinstance(node, ast.Assign) else [node.target]
            rhs = node.value
            if rhs is not None and isinstance(rhs, ast.Constant) and rhs.value is True and any(name == "DEBUG" for target in lhs for name in target_names(target)):
                emit("PYSEC006", "Debug mode enabled", "Medium", "medium", node,
                     "A DEBUG flag is assigned True. Depending on how the application uses it, diagnostics may expose internals.",
                     "Disable debug mode in production and select settings by environment.")

        if not isinstance(node, ast.Call):
            continue
        raw_name = ast.unparse(node.func)
        head, separator, tail = raw_name.partition(".")
        called = aliases.get(head, head) + ("." + tail if separator else "")
        leaf = called.rsplit(".", 1)[-1]

        if leaf in {"eval", "exec"} and called in {leaf, "builtins." + leaf}:
            emit("PYSEC002", f"Dynamic code execution via {leaf}()", "High", "medium", node,
                 f"{leaf}() interprets a string as Python code. If that string can be influenced by untrusted input, arbitrary code may run.",
                 "Avoid dynamic evaluation. Use explicit parsing, a dispatch table, or a restricted data format.")

        if called in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}:
            shell = next((keyword.value for keyword in node.keywords if keyword.arg == "shell"), None)
            if isinstance(shell, ast.Constant) and shell.value is True:
                emit("PYSEC003", "Subprocess invoked with shell=True", "High", "medium", node,
                     "A shell parses the command. If the command includes untrusted values, this can enable command injection; static analysis cannot establish input control.",
                     "Prefer an argument list with shell=False. Validate or allowlist each argument and avoid interpolating untrusted input.")

        if called in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads", "joblib.load"}:
            emit("PYSEC004", "Deserialization of pickle data", "High", "medium", node,
                 "Unpickling untrusted or tampered data can execute attacker-controlled code during deserialization.",
                 "Only unpickle trusted, integrity-protected data. Prefer JSON or another non-executable format for untrusted input.")

        if leaf in {"execute", "executemany"} and node.args:
            query = node.args[0]
            strings = [child.value for child in ast.walk(query) if isinstance(child, ast.Constant) and isinstance(child.value, str)]
            sql_like = any(re.search(r"(?i)\b(select|insert|update|delete|replace)\b", value) for value in strings)
            dynamic = isinstance(query, ast.JoinedStr) or (isinstance(query, ast.BinOp) and isinstance(query.op, (ast.Add, ast.Mod))) or (isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "format")
            if sql_like and dynamic:
                emit("PYSEC005", "SQL query assembled dynamically", "High", "medium", node,
                     "SQL-looking text is combined with a dynamic expression before execution. This can create injection risk if the value is untrusted; its origin cannot be proven statically.",
                     "Use parameterized queries for values. Allowlist identifiers that cannot be parameterized.")

        file_sink = leaf in {"open", "Path", "PurePath"} or called in {"os.open", "pathlib.Path"} or (isinstance(node.func, ast.Attribute) and leaf == "open")
        if file_sink and node.args and any(isinstance(child, ast.Attribute) and child.attr in {"args", "query_params", "path_params", "form", "GET"} for child in ast.walk(node.args[0])):
            emit("PYSEC007", "Request-derived file path", "Medium", "low", node,
                 "A file path appears to include a request field. Without validation, path traversal may reach files outside the intended directory.",
                 "Resolve the path against an allowed base directory, verify it remains beneath that base, and reject traversal segments.")

        if leaf == "run" and isinstance(node.func, ast.Attribute) and any(keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
            emit("PYSEC006", "Debug mode enabled", "Medium", "medium", node,
                 "A server run call enables debug mode. Diagnostic output may reveal internals.",
                 "Disable debug mode in production and select settings by environment.")

    unique = {}
    for finding in findings:
        unique[(finding["rule_id"], finding["line"], finding["title"])] = finding
    return list(unique.values())
