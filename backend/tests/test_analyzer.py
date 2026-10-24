import io
import stat
import zipfile
import pytest
from fastapi.testclient import TestClient
from analyzer import AnalysisError, MAX_FILE, analyze
from main import app, demo_zip

def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for name, source in files.items():
            z.writestr(name, source)
    return buffer.getvalue()

def test_demo_routes_calls_cycles_and_docs():
    result = analyze(demo_zip(), "demo.zip")
    assert result["stats"]["modules"] == 7
    assert "router = APIRouter" in next(m["source"] for m in result["modules"] if m["id"] == "atlas.routes")
    assert {r["path"] for r in result["routes"]} == {"/health", "/api/v1/items/", "/api/v1/items/{item_id}"}
    assert len(result["routes"]) == 5
    assert all(r["mounted"] for r in result["routes"])
    assert ["atlas.repository", "atlas.service"] in result["cycles"]
    assert any(e["source"] == "atlas.routes:get_items" and e["target"] == "atlas.service:list_items" for e in result["edges"])
    assert result["stats"]["missing_docstrings"] == 4
    assert {item["rule_id"] for item in result["security_findings"]} >= {"PYSEC002", "PYSEC005"}
    assert "POST /api/v1/items/" in result["markdown"]

@pytest.mark.parametrize("path", ["../evil.py", "/evil.py", "C:/evil.py", "a\\evil.py"])
def test_unsafe_paths(path):
    with pytest.raises(AnalysisError, match="unsafe"):
        analyze(archive({path.replace(chr(92), "/"): "x=1"}).replace(b"a/evil.py", b"a" + bytes([92]) + b"evil.py") if chr(92) in path else archive({path: "x=1"}))

def test_symlink():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        info = zipfile.ZipInfo("evil.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "target")
    with pytest.raises(AnalysisError, match="symbolic"):
        analyze(buffer.getvalue())

def test_bad_zip_empty_and_oversize():
    for data in [b"not zip", archive({"readme.md": "hello"}), archive({"big.py": "x" * (MAX_FILE + 1)})]:
        with pytest.raises(AnalysisError):
            analyze(data)

def test_source_never_executes(tmp_path):
    marker = tmp_path / "executed"
    result = analyze(archive({"danger.py": f"open({str(marker)!r}, 'w').write('bad')\nraise Exception('boom')"}))
    assert len(result["modules"]) == 1
    assert not marker.exists()

def test_syntax_and_encoding_are_findings():
    result = analyze(archive({"bad.py": "def broken(", "encoded.py": b"\xff"}))
    assert {f["kind"] for f in result["findings"]} == {"syntax", "encoding"}

def test_alias_router_multiple_mounts_and_dynamic_path():
    result = analyze(archive({"main.py": '''from fastapi import FastAPI as API, APIRouter as Router
app = API()
router = Router(prefix="/things")
app.include_router(router, prefix="/v1")
app.include_router(router, prefix="/v2")
@router.api_route("/all", methods=["GET", "POST"])
def all_things():
    """List things."""
    pass
@router.get(PATH)
def dynamic(): pass
'''}))
    assert len(result["routes"]) == 4
    assert {r["path"] for r in result["routes"]} == {"/v1/things/all", "/v2/things/all"}
    assert any(f["kind"] == "dynamic_route" for f in result["findings"])

def test_non_fastapi_decorators_ignored_and_unmounted_labeled():
    result = analyze(archive({"main.py": '''from fastapi import APIRouter
router = APIRouter(prefix="/x")
@router.get("/")
def real(): pass
@other.get("/fake")
def fake(): pass
'''}))
    assert len(result["routes"]) == 1
    assert result["routes"][0]["mounted"] is False

def test_relative_imports():
    result = analyze(archive({"repo/pkg/__init__.py": "", "repo/pkg/a.py": "from .b import hello\n\ndef run(): return hello()", "repo/pkg/b.py": "from . import a\n\ndef hello(): return 1"}))
    assert ["pkg.a", "pkg.b"] in result["cycles"]
    assert any(e["kind"] == "call" for e in result["edges"])

def test_api_upload_and_download():
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        data = client.get("/api/demo/download")
        assert data.headers["content-type"] == "application/zip"
        response = client.post("/api/analyze?filename=test.zip", content=data.content, headers={"content-type": "application/zip"})
        assert response.status_code == 200
        assert response.json()["name"] == "test"
        assert client.post("/api/analyze", content=b"bad", headers={"content-type": "application/zip"}).status_code == 400
        assert client.post("/api/analyze", content=b"bad").status_code == 415
        assert client.post("/api/analyze", content=b"x" * (10 * 1024 * 1024 + 1), headers={"content-type": "application/zip"}).status_code == 413
        demo = client.get("/api/demo")
        assert demo.status_code == 200
        assert {item["rule_id"] for item in demo.json()["security_findings"]} >= {"PYSEC002", "PYSEC005"}

def test_dynamic_methods_and_mount_prefix_are_flagged():
    result = analyze(archive({"main.py": '''from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()
app.include_router(router, prefix=PREFIX)
@router.api_route("/", methods=METHODS)
def dynamic(): pass
'''}))
    assert not result["routes"]
    assert sum(f["kind"] == "dynamic_route" for f in result["findings"]) == 2

def test_nested_router_prefixes():
    result = analyze(archive({"main.py": '''from fastapi import FastAPI, APIRouter
app = FastAPI()
parent = APIRouter(prefix="/parent")
child = APIRouter(prefix="/child")
parent.include_router(child, prefix="/nested")
app.include_router(parent, prefix="/api")
@child.get("/item")
def item(): pass
'''}))
    assert result["routes"][0]["path"] == "/api/parent/nested/child/item"

def test_no_html_in_generated_markdown():
    result = analyze(archive({"x.py": '"""<script>alert(1)</script>"""\n'}))
    assert "<script>" not in result["markdown"]
    assert "&lt;script&gt;" in result["markdown"]

def test_symbol_details_call_chain_and_edge_locations():
    result = analyze(archive({"chain.py": '''"""A small call chain."""
def leaf(value: int = 2) -> int:
    return value

def middle(value):
    return leaf(value)

def entry():
    return middle()
'''}))
    leaf = next(symbol for symbol in result["symbols"] if symbol["name"] == "leaf")
    assert leaf["parameters"] == [{"name": "value", "kind": "positional_or_keyword", "annotation": "int", "default": "2"}]
    assert leaf["return_annotation"] == "int"
    assert leaf["return_expressions"] == [{"line": 3, "expression": "value"}]
    by_id = {symbol["name"]: symbol["id"] for symbol in result["symbols"]}
    calls = [edge for edge in result["edges"] if edge["kind"] == "call"]
    assert {(edge["source"], edge["target"]) for edge in calls} == {
        (by_id["middle"], by_id["leaf"]), (by_id["entry"], by_id["middle"])
    }
    assert all(edge["file"] == "chain.py" and edge["line"] for edge in calls)


def test_function_with_no_relationships_has_no_call_edges():
    result = analyze(archive({"quiet.py": '''"""A quiet module."""
def isolated(value):
    return value
'''}))
    isolated = next(symbol for symbol in result["symbols"] if symbol["name"] == "isolated")
    assert not [edge for edge in result["edges"] if edge["kind"] == "call" and (edge["source"] == isolated["id"] or edge["target"] == isolated["id"])]


def test_security_scanner_flags_patterns_redacts_credentials_and_skips_safe_cases():
    source = '''"""Security pattern examples."""
import pickle as p
import subprocess as sp
API_KEY = "abcDEF98765-QWER123"
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
not-a-real-demo-key-material
-----END PRIVATE KEY-----"""
PLACEHOLDER_TOKEN = "your_api_key_here"
DEBUG = True

def dangerous(expression, command, payload, cursor, value, request):
    result = eval(expression)
    exec(expression)
    sp.run(command, shell=True)
    restored = p.loads(payload)
    cursor.execute(f"SELECT * FROM records WHERE name = '{value}'")
    cursor.execute("SELECT * FROM records WHERE id = %s", (value,))
    return open(request.query_params["path"]).read()
'''
    result = analyze(archive({"security.py": source}))
    findings = result["security_findings"]
    rules = {finding["rule_id"] for finding in findings}
    assert {"PYSEC001", "PYSEC002", "PYSEC003", "PYSEC004", "PYSEC005", "PYSEC006", "PYSEC007"} <= rules
    credential = next(finding for finding in findings if finding["rule_id"] == "PYSEC001")
    assert "abcDEF98765-QWER123" not in credential["snippet"]
    assert "[REDACTED]" in credential["snippet"]
    credential_snippets = [finding["snippet"] for finding in findings if finding["rule_id"] == "PYSEC001"]
    assert any("PRIVATE_KEY = '[REDACTED]'" in snippet for snippet in credential_snippets)
    assert all("not-a-real-demo-key-material" not in snippet for snippet in credential_snippets)
    sql = [finding for finding in findings if finding["rule_id"] == "PYSEC005"]
    assert len(sql) == 1
    assert all(finding["confidence"] != "confirmed" for finding in findings)
    assert all(finding["file"] == "security.py" and finding["line"] > 0 for finding in findings)
    assert all(finding["remediation"] for finding in findings)


def test_security_scanner_does_not_flag_placeholder_credentials_or_parameterized_sql():
    result = analyze(archive({"safe.py": '''"""Safe examples."""
API_KEY = "your_api_key_here"
PASSWORD = "replace-this-value"
def query(cursor, value):
    return cursor.execute("SELECT * FROM records WHERE id = %s", (value,))
'''}))
    assert result["security_findings"] == []


def test_syntax_error_is_reported_and_scanner_continues_with_other_files():
    result = analyze(archive({"broken.py": "def broken(:", "valid.py": '''"""A valid file."""
def run():
    return eval("1")
'''}))
    assert any(finding["kind"] == "syntax" and finding["file"] == "broken.py" for finding in result["findings"])
    assert any(finding["rule_id"] == "PYSEC002" and finding["file"] == "valid.py" for finding in result["security_findings"])
