# AutoDoc AI

A local, source-grounded documentation workbench for Python repositories. Built with React 19, Vite, TypeScript, Tailwind CSS, React Flow, and FastAPI.

## Quick start (Windows PowerShell)

Requirements: Python 3.11+ and Node.js 20.19+ or 22+. Open a terminal in this project folder.

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
    cd frontend
    npm.cmd ci
    npm.cmd run build
    cd ..
    .\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000

Open http://127.0.0.1:8000 and click **Try the demo project**. Keep the terminal running. Press Ctrl+C to stop. The built frontend is served by FastAPI, so this demo needs only one server.

The delivered folder includes a prebuilt frontend in frontend/dist. After installing Python requirements you can skip the npm steps to run that version immediately.

## macOS / Linux

    python3 -m venv .venv
    .venv/bin/python -m pip install -r backend/requirements.txt
    cd frontend
    npm ci
    npm run build
    cd ..
    .venv/bin/python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000

## Development with hot reload

Run the backend above with --reload. In a second terminal:

    cd frontend
    npm.cmd run dev

Open the URL printed by Vite (usually http://127.0.0.1:5173). Its /api proxy forwards to the backend on port 8000. On macOS/Linux use npm instead of npm.cmd.

## Demo walkthrough (about two minutes)

1. The Atlas demo loads automatically: 7 modules, 14 symbols, 5 routes, and 81% docstring coverage.
2. Explore the central dependency graph. Cyan nodes are modules, purple nodes are functions, and gold nodes are classes. Amber markers indicate circular import groups.
3. Select a file or symbol in the explorer or graph. The code inspector shows actual Python source, syntax colors, line numbers, and declaration notes. Selecting a symbol highlights its definition.
4. Use Filters to show or hide node types, or choose 1-hop / 2-hop focus around the current selection. Search filters modules and symbols.
5. Open API in the right panel and expand POST /api/v1/items/. Inspect its signature, response model, status, and source link.
6. Select a function in the Explorer or graph. In the Code inspector, run **Analyze Impact** and distinguish direct callers, transitive callers, module imports, and affected modules. Choose **Explain This Function** to see/copy a deterministic explanation.
7. Open **Security** to review the synthetic eval/SQL examples, severity, confidence, redacted snippets, remediation, and source links. These sample functions are never called.
8. Open Quality for four missing docstrings and one import cycle. Click a finding to inspect its source.
9. Open Docs to download Markdown or JSON. The top Export docs button is always available after analysis.
10. The bottom-right question box answers structured questions about endpoints, cycles, missing docs, and exact module names using parsed facts, without an external AI service.
11. Use Upload ZIP to analyze demo/atlas-api.zip or another Python repository.

On narrow screens, use the Explorer / Code / Graph / Insights tabs. The source inspector can be hidden to give the graph more room. The sample deliberately includes a circular import and synthetic security-pattern examples; it is intended as analysis input, not a runnable service.

## Included behavior

- Click-to-upload and drag-and-drop ZIPs, loading state, and actionable errors.
- AST parsing; module/function/class discovery, signatures, docstrings, line references.
- Dark four-pane workbench, syntax-highlighted source inspector, and interactive React Flow module/symbol graph with type filters, search, focus depth, zoom, and fit.
- FastAPI/APIRouter aliases, common HTTP decorators, api_route, async handlers, literal prefixes, nested mounts, and multiple mounts.
- Missing docstrings, syntax/encoding issues, dynamic route findings, and strongly connected import groups.
- Change impact tracing over statically detected call edges, with imports labeled separately and transitive callers marked as inferred.
- Deterministic function/class explanations from AST metadata, docstrings, and detected relationships; no language model is used.
- Conservative security patterns for hardcoded credential-like assignments, eval/exec, shell=True subprocess calls, pickle deserialization, dynamically assembled SQL, debug mode, and request-derived file paths. Findings include redacted snippets, severity, confidence, risk, remediation, and source links.
- Deterministic Markdown reference and full JSON downloads generated in memory.
- Demo endpoint and downloadable sample; no account, API key, database, or network AI service.

## API

- GET /api/health: health status.
- POST /api/analyze?filename=my-project.zip: raw ZIP bytes, Content-Type: application/zip; returns analysis including Markdown.
- GET /api/demo: analyze the bundled sample, including synthetic security examples.

- GET /api/demo/download: download the sample ZIP.
- /docs: FastAPI interactive API documentation.

The analysis response adds backward-compatible `security_findings`, symbol metadata (`parameters`, `return_annotation`, `return_expressions`, decorators, bases, imports), and source locations on relationship edges.

Example:

    curl -X POST "http://127.0.0.1:8000/api/analyze?filename=atlas-api.zip" -H "Content-Type: application/zip" --data-binary "@demo/atlas-api.zip"

## Verification

From the project root with requirements installed:

    python -m pytest -q
    cd frontend
    npm.cmd run build

Tests cover traversal, original Windows ZIP paths, symlinks, invalid/empty/oversized archives, proof source is not executed, syntax/encoding errors, relative imports, call edges, cycles, router aliases/prefixes/multiple mounts, dynamic declarations, HTML escaping, and HTTP upload/download/error responses. See VERIFICATION.md for delivery results.

## Safety and analysis boundaries

Source is read from ZIP streams in memory. It is never extracted, imported, evaluated, installed, or executed. Uploads and results are not persisted by the backend. Downloads are saved only when requested. No code is sent to a third-party provider.

Limits: 10 MB compressed upload, 20 MB total declared uncompressed archive, 2,000 archive entries, 300 Python files, 512 KB per Python file, and 50,000 AST nodes per file. Size is checked while streaming. Suspicious compression ratios, traversal/drive paths, backslashes, duplicate paths, symbolic links, and encrypted archives are rejected. Dependency/cache folders are ignored. Two analyses can run concurrently.

This is a local hackathon MVP, not a hardened public upload service. The parser operates in-process; there is no OS-isolated worker or hard CPU timeout. Keep the bind address at 127.0.0.1. Public deployment would need isolated analysis workers, proxy request/concurrency limits, and authentication.

Security findings are heuristic indicators, not confirmed vulnerabilities. Static checks do not trace tainted values, prove exploitability, inspect runtime configuration, or establish that a clean scan is secure. Credential-like snippets are redacted in findings; the regular source inspector still shows the uploaded source to the local user.

“AI” is the product name. This version uses deterministic AST analysis, not a language model; it does not invent explanations or schemas. Markdown includes source docstrings, declarations, and findings.

Dynamic imports, monkey patches, re-exported routers, factory-created apps, conditional definitions, local name shadowing, and object-method dispatch are not fully resolved. Nested-scope imports are treated as possible module dependencies. The call edges show statically resolved direct calls, not a runtime trace. Module-to-symbol edges show containment. Source text is returned to the browser for the code inspector and is included in JSON exports. Graphs show at most 150 matching nodes; search narrows the view. Import cycles are strongly connected groups, not ordered execution paths. Unmounted routers are labeled; computed route paths/methods/prefixes are flagged.

The API reference is not a complete OpenAPI specification. It does not infer Pydantic schemas, inherited router dependencies, authorization policies, or runtime response behavior. Docstring coverage counts modules and discovered symbols, including private functions and methods.

## Structure

- backend/analyzer.py: archive validation, AST analysis, graphs/cycles, Markdown generation.
- backend/intelligence.py: source-grounded symbol metadata and conservative security pattern checks.
- backend/main.py: stateless API and optional built frontend.
- backend/tests/: regression and safety tests.
- frontend/src/main.tsx: typed React views and React Flow integration.
- frontend/src/style.css: responsive visual system with Tailwind.
- sample/atlas/: demo Python source.
- demo/: uploadable ZIP and example docs/JSON.
- frontend/package-lock.json: reproducible frontend dependencies.

## Troubleshooting

- **Cannot reach analyzer:** start FastAPI on port 8000; use the Vite URL during development.
- **Port in use:** stop the prior server, or change the backend port and frontend/vite.config.ts.
- **Blank root / 404:** build the frontend before starting FastAPI, then restart it.
- **npm blocked in PowerShell:** use npm.cmd, as shown above.
- **No Python source found:** ZIP source files, not only README or compiled files.
- **Syntax findings:** use a Python version compatible with the uploaded source.
