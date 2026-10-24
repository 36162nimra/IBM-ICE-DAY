# Verification — 24 October 2026

## Current implementation checks

- Backend: **21 tests passed** on Python 3.12.10. Coverage includes archive/path safety, source non-execution, syntax errors, symbol parameters and return metadata, call chains and edge locations, no-relationship symbols, credential redaction (including multiline keys), eval/exec, subprocess shell usage, pickle, dynamic SQL, debug mode, request-derived paths, safe parameterized SQL/placeholders, demo analysis, and HTTP upload/download/error behavior.
- Frontend: `npm.cmd ci --no-audit --no-fund` installed the locked dependencies; `npm.cmd run build` passed TypeScript compilation and the Vite production build.
- Demo: 7 modules, 14 symbols, 5 routes, 81% docstring coverage, 4 missing docstrings, 1 import cycle, and 2 intentionally synthetic security findings.
- API: regression tests verify `/api/health`, `/api/demo`, `/api/demo/download`, and ZIP upload/error paths.

The test run emitted one upstream Starlette/httpx deprecation warning from `fastapi.testclient`; it did not affect results. Frontend automation tests are not configured in the current project, so the UI was type-checked and production-built but the new interactions were not browser-automated in this update.

## Manual review limits

The impact, explanation, and security panels have not been manually exercised in a browser after this update. Upload-picker, drag-and-drop, and mobile touch interactions were not manually verified. Security findings are heuristic patterns, not proof of exploitability or a guarantee that a clean scan is secure.

## Repeat checks

From the project root:

    python -m pytest -q
    cd frontend
    npm.cmd ci
    npm.cmd run build

Manual walkthrough: load the Atlas demo, select `atlas.service:normalize_name`, run Analyze Impact, open Explain This Function, review Security findings and their redacted source links, then try a ZIP upload and export Markdown/JSON.
