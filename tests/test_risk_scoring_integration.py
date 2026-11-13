
import json

import src.risk_scoring as risk_scoring


def test_complete_risk_scoring_workflow(tmp_path, monkeypatch):
    # 1. Prepare sample alert
    alert = {
        "alert_id": "TEST-001",
        "severity": "High"
    }

    # 2. Prepare threat intelligence results
    enrichment = {
        "ip_enrichment": [
            {
                "ip": "8.8.8.8",
                "virustotal": {
                    "status": "success",
                    "analysis_stats": {
                        "malicious": 2
                    }
                },
                "abuseipdb": {
                    "status": "success",
                    "abuse_confidence_score": 80,
                    "total_reports": 25
                }
            }
        ]
    }

    # 3. Create temporary input and output files
    alert_file = tmp_path / "normalized_alert.json"
    enrichment_file = tmp_path / "enriched_iocs.json"
    output_file = tmp_path / "risk_assessment.json"

    alert_file.write_text(
        json.dumps(alert),
        encoding="utf-8"
    )

    enrichment_file.write_text(
        json.dumps(enrichment),
        encoding="utf-8"
    )

    # 4. Redirect module paths to temporary files
    monkeypatch.setattr(risk_scoring, "ALERT_FILE", alert_file)
    monkeypatch.setattr(risk_scoring, "ENRICHMENT_FILE", enrichment_file)
    monkeypatch.setattr(risk_scoring, "OUTPUT_FILE", output_file)

    # 5. Execute the actual scoring workflow
    risk_scoring.main()

    # 6. Verify generated output
    assert output_file.exists()

    result = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    # Expected calculation:
    # High severity       = 22
    # VirusTotal          = 20
    # AbuseIPDB confidence = 20
    # Report volume       = 6
    # Data quality        = 0
    # Total                = 68

    assert result["alert_id"] == "TEST-001"
    assert result["overall_risk_score"] == 68
    assert result["overall_risk_level"] == "High"

    assert len(result["ip_assessments"]) == 1

    ip_result = result["ip_assessments"][0]

    assert ip_result["ip"] == "8.8.8.8"
    assert ip_result["risk_score"] == 68
    assert ip_result["risk_level"] == "High"

    factors = ip_result["factors"]

    assert factors["virustotal"]["points"] == 20
    assert factors["abuseipdb"]["confidence_points"] == 20
    assert factors["abuseipdb"]["report_volume_points"] == 6

    assert factors["data_quality"]["points"] == 0
    assert factors["data_quality"]["successful_sources"] == 2
    assert factors["data_quality"]["coverage"] == "Complete"

    assert (
        "Threat intelligence coverage does not contribute risk points"
        in result["scoring_note"]
    )


def test_empty_ip_enrichment_uses_severity_score(tmp_path, monkeypatch):
    alert = {
        "alert_id": "TEST-002",
        "severity": "Medium"
    }

    enrichment = {
        "ip_enrichment": []
    }

    alert_file = tmp_path / "normalized_alert.json"
    enrichment_file = tmp_path / "enriched_iocs.json"
    output_file = tmp_path / "risk_assessment.json"

    alert_file.write_text(
        json.dumps(alert),
        encoding="utf-8"
    )

    enrichment_file.write_text(
        json.dumps(enrichment),
        encoding="utf-8"
    )

    monkeypatch.setattr(risk_scoring, "ALERT_FILE", alert_file)
    monkeypatch.setattr(risk_scoring, "ENRICHMENT_FILE", enrichment_file)
    monkeypatch.setattr(risk_scoring, "OUTPUT_FILE", output_file)

    risk_scoring.main()

    result = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert result["alert_id"] == "TEST-002"
    assert result["overall_risk_score"] == 15
    assert result["overall_risk_level"] == "Low"
    assert result["ip_assessments"] == []


def test_highest_ip_score_determines_overall_risk(
    tmp_path,
    monkeypatch
):
    alert = {
        "alert_id": "TEST-003",
        "severity": "Low"
    }

    enrichment = {
        "ip_enrichment": [
            {
                "ip": "8.8.8.8",
                "virustotal": {
                    "status": "success",
                    "analysis_stats": {
                        "malicious": 0
                    }
                },
                "abuseipdb": {
                    "status": "success",
                    "abuse_confidence_score": 0,
                    "total_reports": 0
                }
            },
            {
                "ip": "1.2.3.4",
                "virustotal": {
                    "status": "success",
                    "analysis_stats": {
                        "malicious": 3
                    }
                },
                "abuseipdb": {
                    "status": "success",
                    "abuse_confidence_score": 80,
                    "total_reports": 25
                }
            }
        ]
    }

    alert_file = tmp_path / "normalized_alert.json"
    enrichment_file = tmp_path / "enriched_iocs.json"
    output_file = tmp_path / "risk_assessment.json"

    alert_file.write_text(
        json.dumps(alert),
        encoding="utf-8"
    )

    enrichment_file.write_text(
        json.dumps(enrichment),
        encoding="utf-8"
    )

    monkeypatch.setattr(risk_scoring, "ALERT_FILE", alert_file)
    monkeypatch.setattr(risk_scoring, "ENRICHMENT_FILE", enrichment_file)
    monkeypatch.setattr(risk_scoring, "OUTPUT_FILE", output_file)

    risk_scoring.main()

    result = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    # First IP: 5 severity + 0 intelligence = 5
    # Second IP: 5 + 30 + 20 + 6 + 0 = 61
    # Overall score uses the highest IP score, not their sum.

    assert result["overall_risk_score"] == 61
    assert result["overall_risk_level"] == "High"

    assert len(result["ip_assessments"]) == 2

    assert result["ip_assessments"][0]["risk_score"] == 5
    assert result["ip_assessments"][1]["risk_score"] == 61
