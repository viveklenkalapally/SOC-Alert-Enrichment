
from unittest import result

import pytest

from src.risk_scoring import (
    assess_ip,
    calculate_report_points,
    get_risk_level,
    get_recommendation
)


# --------------------------------------------------
# 1. VIRUSTOTAL TESTS
# --------------------------------------------------

def test_virustotal_malicious_detection():
    ip_data = {
        "ip": "8.8.8.8",
        "virustotal": {
            "status": "success",
            "analysis_stats": {
                "malicious": 2
            }
        },
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 0,
            "total_reports": 0
        }
    }

    result = assess_ip(ip_data)

    assert result["factors"]["virustotal"]["points"] == 20


def test_virustotal_points_are_capped_at_30():
    ip_data = {
        "ip": "8.8.8.8",
        "virustotal": {
            "status": "success",
            "analysis_stats": {
                "malicious": 10
            }
        }
    }

    result = assess_ip(ip_data)

    assert result["factors"]["virustotal"]["points"] == 30


def test_virustotal_unavailable():
    ip_data = {
        "ip": "8.8.8.8",
        "virustotal": {
            "status": "error"
        }
    }

    result = assess_ip(ip_data)

    assert result["factors"]["virustotal"]["points"] == 0
    assert result["factors"]["virustotal"]["status"] == "error"


# --------------------------------------------------
# 2. ABUSEIPDB TESTS
# --------------------------------------------------

def test_abuseipdb_confidence_scoring():
    ip_data = {
        "ip": "8.8.8.8",
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 80,
            "total_reports": 0
        }
    }

    result = assess_ip(ip_data)

    assert result["factors"]["abuseipdb"]["confidence_points"] == 20


def test_historical_reports_without_confidence_add_no_points():
    result = calculate_report_points(
        total_reports=193,
        confidence=0
    )

    assert result == 0


def test_report_volume_scoring():
    assert calculate_report_points(5, 50) == 3
    assert calculate_report_points(25, 50) == 6
    assert calculate_report_points(100, 50) == 10


# --------------------------------------------------
# 3. DATA QUALITY TESTS
# --------------------------------------------------

def test_both_intelligence_sources_successful():
    ip_data = {
        "ip": "8.8.8.8",
        "virustotal": {"status": "success"},
        "abuseipdb": {"status": "success"}
    }

    result = assess_ip(ip_data)

    assert result["factors"]["data_quality"]["points"] == 0
    assert result["factors"]["data_quality"]["successful_sources"] == 2
    assert result["factors"]["data_quality"]["coverage"] == "Complete"
    assert result["risk_score"] == 0


def test_no_intelligence_sources_successful():
    ip_data = {
        "ip": "8.8.8.8",
        "virustotal": {"status": "error"},
        "abuseipdb": {"status": "error"}
    }

    result = assess_ip(ip_data)

    assert result["factors"]["data_quality"]["points"] == 0


# --------------------------------------------------
# 4. RISK LEVEL TESTS
# --------------------------------------------------

@pytest.mark.parametrize(
    "score, expected",
    [
        (0, "Low"),
        (24, "Low"),
        (25, "Medium"),
        (49, "Medium"),
        (50, "High"),
        (74, "High"),
        (75, "Critical"),
        (100, "Critical")
    ]
)
def test_risk_level_thresholds(score, expected):
    assert get_risk_level(score) == expected


# --------------------------------------------------
# 5. RECOMMENDATION TESTS
# --------------------------------------------------

def test_critical_recommendation():
    assert get_recommendation("Critical") == (
        "Immediate investigation and escalation."
    )


def test_low_recommendation():
    assert get_recommendation("Low") == (
        "Continue monitoring and retain evidence."
    )
