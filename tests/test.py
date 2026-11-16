"""
Test suite for the Metadata Extractor project.

Groups:
  1 — Server health
  2 — True positives (tool detects vulnerable files)
  3 — False positives (tool does NOT flag clean files)
  4 — Output format validation
  5 — Edge cases
"""

import json
import subprocess
import sys
import os

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server.main import app, start  # noqa: E402

BASE_URL: str = ""
_server = None


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server
    port = 3791
    BASE_URL = f"http://127.0.0.1:{port}"
    _server = start(port)
    yield
    _server.should_exit = True


def _run_tool(target: str = "") -> subprocess.CompletedProcess:
    t = target or BASE_URL
    tool_path = os.path.join(os.path.dirname(__file__), "..", "tool", "main.py")
    return subprocess.run(
        [sys.executable, tool_path, "--target", t],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def _tool_output(target: str = "") -> dict:
    result = _run_tool(target)
    assert result.returncode == 0, f"Tool exited with code {result.returncode}: {result.stderr}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Group 1 — Server health
# ---------------------------------------------------------------------------


def test_health_endpoint_returns_200():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.status_code == 200


def test_health_endpoint_returns_ok_json():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.json() == {"status": "ok"}


def test_files_endpoint_returns_200():
    r = httpx.get(f"{BASE_URL}/files")
    assert r.status_code == 200


def test_files_endpoint_lists_all_four_files():
    r = httpx.get(f"{BASE_URL}/files")
    files = r.json()["files"]
    assert "vuln_photo.jpg" in files
    assert "safe_photo.jpg" in files
    assert "vuln_document.pdf" in files
    assert "safe_document.pdf" in files


def test_vuln_jpeg_served_as_jpeg():
    r = httpx.get(f"{BASE_URL}/files/vuln_photo.jpg")
    assert r.status_code == 200
    assert "image/jpeg" in r.headers.get("content-type", "")


def test_vuln_pdf_served_as_pdf():
    r = httpx.get(f"{BASE_URL}/files/vuln_document.pdf")
    assert r.status_code == 200
    assert "application/pdf" in r.headers.get("content-type", "")


def test_missing_file_returns_404():
    r = httpx.get(f"{BASE_URL}/files/nonexistent.jpg")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Group 2 — True positives
# ---------------------------------------------------------------------------


def test_tool_detects_gps_in_vuln_photo():
    output = _tool_output()
    gps_findings = [
        f for f in output["findings"]
        if "GPS" in f["vulnerability_type"] and "vuln_photo" in f["endpoint"]
    ]
    assert len(gps_findings) >= 1, "Expected GPS finding for vuln_photo.jpg"


def test_gps_finding_is_high_severity():
    output = _tool_output()
    gps_findings = [
        f for f in output["findings"]
        if "GPS" in f["vulnerability_type"] and "vuln_photo" in f["endpoint"]
    ]
    assert gps_findings[0]["severity"] == "HIGH"


def test_tool_detects_email_in_vuln_photo():
    output = _tool_output()
    email_findings = [
        f for f in output["findings"]
        if "Email" in f["vulnerability_type"] and "vuln_photo" in f["endpoint"]
    ]
    assert len(email_findings) >= 1, "Expected email finding in vuln_photo.jpg EXIF"
    assert "@" in email_findings[0]["evidence"]


def test_tool_detects_software_version_in_vuln_photo():
    output = _tool_output()
    sw_findings = [
        f for f in output["findings"]
        if "Software" in f["vulnerability_type"] and "vuln_photo" in f["endpoint"]
    ]
    assert len(sw_findings) >= 1, "Expected software version finding in vuln_photo.jpg"


def test_tool_detects_sensitive_label_in_vuln_pdf():
    output = _tool_output()
    label_findings = [
        f for f in output["findings"]
        if "Sensitive" in f["vulnerability_type"] and "vuln_document" in f["endpoint"]
    ]
    assert len(label_findings) >= 1, "Expected confidential label finding in vuln_document.pdf"
    assert label_findings[0]["severity"] == "HIGH"


def test_tool_detects_email_in_vuln_pdf():
    output = _tool_output()
    email_findings = [
        f for f in output["findings"]
        if "Email" in f["vulnerability_type"] and "vuln_document" in f["endpoint"]
    ]
    assert len(email_findings) >= 1, "Expected email finding in vuln_document.pdf metadata"


def test_tool_detects_software_version_in_vuln_pdf():
    output = _tool_output()
    sw_findings = [
        f for f in output["findings"]
        if "Software" in f["vulnerability_type"] and "vuln_document" in f["endpoint"]
    ]
    assert len(sw_findings) >= 1, "Expected software version finding in vuln_document.pdf"


def test_total_findings_count_is_positive():
    output = _tool_output()
    assert len(output["findings"]) > 0


# ---------------------------------------------------------------------------
# Group 3 — False positives
# ---------------------------------------------------------------------------


def test_tool_does_not_flag_safe_photo():
    output = _tool_output()
    safe_findings = [f for f in output["findings"] if "safe_photo" in f["endpoint"]]
    assert safe_findings == [], f"Tool incorrectly flagged safe_photo.jpg: {safe_findings}"


def test_tool_does_not_flag_safe_pdf():
    output = _tool_output()
    safe_findings = [f for f in output["findings"] if "safe_document" in f["endpoint"]]
    assert safe_findings == [], f"Tool incorrectly flagged safe_document.pdf: {safe_findings}"


def test_safe_files_produce_no_gps_findings():
    output = _tool_output()
    gps_safe = [
        f for f in output["findings"]
        if "GPS" in f["vulnerability_type"] and "safe" in f["endpoint"]
    ]
    assert gps_safe == []


# ---------------------------------------------------------------------------
# Group 4 — Output format
# ---------------------------------------------------------------------------


def test_output_is_valid_json():
    result = _run_tool()
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(f"Tool stdout is not valid JSON: {exc}")


def test_output_has_target_field():
    output = _tool_output()
    assert "target" in output
    assert output["target"] == BASE_URL


def test_output_has_findings_field():
    output = _tool_output()
    assert "findings" in output
    assert isinstance(output["findings"], list)


def test_output_has_summary_field():
    output = _tool_output()
    assert "summary" in output
    assert isinstance(output["summary"], str)
    assert len(output["summary"]) > 0


def test_each_finding_has_required_fields():
    output = _tool_output()
    required = {"endpoint", "vulnerability_type", "evidence", "severity"}
    for finding in output["findings"]:
        missing = required - set(finding.keys())
        assert not missing, f"Finding missing fields {missing}: {finding}"


def test_severity_values_are_valid():
    output = _tool_output()
    valid_severities = {"HIGH", "MEDIUM", "LOW"}
    for finding in output["findings"]:
        assert finding["severity"] in valid_severities, (
            f"Invalid severity '{finding['severity']}' in finding: {finding}"
        )


def test_endpoint_values_start_with_slash():
    output = _tool_output()
    for finding in output["findings"]:
        assert finding["endpoint"].startswith("/"), (
            f"endpoint should be a path, got: {finding['endpoint']}"
        )


# ---------------------------------------------------------------------------
# Group 5 — Edge cases
# ---------------------------------------------------------------------------


def test_unreachable_server_does_not_crash():
    result = _run_tool("http://127.0.0.1:19999")
    assert result.returncode == 0, "Tool should exit 0 even when server is unreachable"


def test_unreachable_server_returns_empty_findings():
    result = _run_tool("http://127.0.0.1:19999")
    output = json.loads(result.stdout)
    assert output["findings"] == []


def test_unreachable_server_returns_valid_json():
    result = _run_tool("http://127.0.0.1:19999")
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail("Tool did not return valid JSON for unreachable server")


def test_tool_handles_trailing_slash_in_target():
    result = _run_tool(BASE_URL + "/")
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "findings" in output
