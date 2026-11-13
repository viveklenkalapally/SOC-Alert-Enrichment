
import json
import os
import subprocess
import sys

from pathlib import Path


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
MAIN_SCRIPT = BASE_DIR / "src" / "main.py"
OUTPUT_DIR = BASE_DIR / "output"


# ============================================================
# FULL PIPELINE INTEGRATION TEST
# ============================================================

def test_full_pipeline_generates_valid_outputs():

    # 1. Configure offline test mode
    test_env = os.environ.copy()
    test_env["SOC_TEST_MODE"] = "1"

    # 2. Execute the complete SOC pipeline
    result = subprocess.run(
        [sys.executable, str(MAIN_SCRIPT)],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=180,
        env=test_env
    )

    # 3. Verify pipeline execution
    assert result.returncode == 0, (
        f"Pipeline execution failed:\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    # Verify that offline mode was actually activated
    assert "OFFLINE TEST MODE ENABLED" in result.stdout, (
        "Pipeline did not activate offline test mode."
    )

    # 4. Verify expected output files
    expected_files = {
        "normalized": OUTPUT_DIR / "normalized_alert.json",
        "extracted": OUTPUT_DIR / "extracted_iocs.json",
        "enriched": OUTPUT_DIR / "enriched_iocs.json",
        "risk": OUTPUT_DIR / "risk_assessment.json",
        "report_json": OUTPUT_DIR / "investigation_report.json",
        "report_html": OUTPUT_DIR / "investigation_report.html"
    }

    for name, file_path in expected_files.items():

        assert file_path.exists(), (
            f"Missing pipeline output: {file_path.name}"
        )

        assert file_path.stat().st_size > 0, (
            f"Empty pipeline output: {file_path.name}"
        )

    # 5. Load generated JSON files
    normalized = json.loads(
        expected_files["normalized"].read_text(
            encoding="utf-8"
        )
    )

    extracted = json.loads(
        expected_files["extracted"].read_text(
            encoding="utf-8"
        )
    )

    enriched = json.loads(
        expected_files["enriched"].read_text(
            encoding="utf-8"
        )
    )

    risk = json.loads(
        expected_files["risk"].read_text(
            encoding="utf-8"
        )
    )

    report = json.loads(
        expected_files["report_json"].read_text(
            encoding="utf-8"
        )
    )

    # 6. Validate alert ID consistency
    alert_id = normalized.get("alert_id")

    assert alert_id, (
        "Normalized alert is missing alert_id."
    )

    assert extracted.get("alert_id") == alert_id

    assert enriched.get("alert_id") == alert_id

    assert risk.get("alert_id") == alert_id

    assert (
        report.get("alert_summary", {}).get("alert_id")
        == alert_id
    )

    # 7. Validate IOC extraction structure
    assert isinstance(extracted.get("ips"), list)

    assert isinstance(extracted.get("urls"), list)

    assert isinstance(extracted.get("domains"), list)

    assert isinstance(extracted.get("hashes"), dict)

    assert all(
        isinstance(extracted["hashes"].get(key), list)
        for key in ["md5", "sha1", "sha256"]
    )

    # 8. Validate enrichment output
    assert enriched.get("enrichment_mode") == "mock"

    assert isinstance(
        enriched.get("ip_enrichment"), list
    )

    for ip_result in enriched["ip_enrichment"]:

        assert ip_result.get("ip")

        assert (
            ip_result.get("virustotal", {}).get("status")
            == "success"
        )

        assert (
            ip_result.get("abuseipdb", {}).get("status")
            == "success"
        )

    # 9. Validate risk assessment
    risk_score = risk.get("overall_risk_score")

    assert isinstance(risk_score, int)

    assert 0 <= risk_score <= 100

    assert risk.get("overall_risk_level") in [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]

    assert risk.get("recommended_action")

    # 10. Validate investigation report
    assert report.get("report_id")

    assert report.get("indicators_of_compromise")

    html_content = expected_files["report_html"].read_text(
        encoding="utf-8"
    )

    assert "<html" in html_content.lower()

    assert "</html>" in html_content.lower()

    # 11. Display validation summary
    print("\n" + "=" * 55)
    print("       FULL PIPELINE VALIDATION SUCCESSFUL")
    print("=" * 55)

    print(f"Alert ID: {alert_id}")
    print(f"Risk score: {risk_score}/100")
    print(f"Risk level: {risk['overall_risk_level']}")
    print(f"Enrichment mode: {enriched['enrichment_mode']}")

    print(
        f"Extracted IPs: {len(extracted['ips'])}"
    )

    print(
        f"Extracted URLs: {len(extracted['urls'])}"
    )

    print(
        f"Extracted domains: {len(extracted['domains'])}"
    )

    print(
        f"Enriched IPs: {len(enriched['ip_enrichment'])}"
    )

    print("All six output files generated and validated.")
    print("=" * 55)

def test_downstream_modules_use_normalized_alert():
    risk_scoring_file = BASE_DIR / "src" / "risk_scoring.py"
    report_generator_file = BASE_DIR / "src" / "report_generator.py"

    risk_code = risk_scoring_file.read_text(encoding="utf-8")
    report_code = report_generator_file.read_text(encoding="utf-8")

    expected_path = (
        'BASE_DIR / "output" / "normalized_alert.json"'
    )

    assert expected_path in risk_code, (
        "Risk scoring must use the normalized alert."
    )

    assert expected_path in report_code, (
        "Report generation must use the normalized alert."
    )