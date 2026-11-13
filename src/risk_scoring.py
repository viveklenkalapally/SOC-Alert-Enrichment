
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "output" / "normalized_alert.json"
ENRICHMENT_FILE = BASE_DIR / "output" / "enriched_iocs.json"
OUTPUT_FILE = BASE_DIR / "output" / "risk_assessment.json"

SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 22,
    "critical": 30
}


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_report_points(total_reports, confidence):
    # Historical reports alone should not increase risk.
    if confidence < 25 or total_reports <= 0:
        return 0

    if total_reports <= 10:
        return 3
    elif total_reports <= 50:
        return 6
    else:
        return 10


def assess_ip(ip_data):
    factors = {}
    reasons = []

    # 1. VirusTotal assessment
    vt = ip_data.get("virustotal", {})
    vt_success = vt.get("status") == "success"

    malicious = 0
    vt_points = 0

    if vt_success:
        stats = vt.get("analysis_stats") or {}
        malicious = max(0, int(stats.get("malicious", 0) or 0))
        vt_points = min(malicious * 10, 30)

        if malicious > 0:
            reasons.append(
                f"VirusTotal reported {malicious} malicious detection(s)."
            )
    else:
        reasons.append("VirusTotal intelligence unavailable.")

    factors["virustotal"] = {
        "status": vt.get("status", "missing"),
        "malicious_detections": malicious,
        "points": vt_points
    }

    # 2. AbuseIPDB assessment
    abuse = ip_data.get("abuseipdb", {})
    abuse_success = abuse.get("status") == "success"

    confidence = 0
    total_reports = 0
    abuse_points = 0
    report_points = 0

    if abuse_success:
        confidence = int(
            abuse.get("abuse_confidence_score", 0) or 0
        )
        total_reports = max(
            0,
            int(abuse.get("total_reports", 0) or 0)
        )

        confidence = max(0, min(confidence, 100))

        abuse_points = round(confidence / 100 * 25)

        report_points = calculate_report_points(
            total_reports, confidence
        )

        if confidence > 0:
            reasons.append(
                f"AbuseIPDB abuse confidence is {confidence}%."
            )

        if total_reports > 0:
            reasons.append(
                f"AbuseIPDB has {total_reports} historical report(s)."
            )
    else:
        reasons.append("AbuseIPDB intelligence unavailable.")

    factors["abuseipdb"] = {
        "status": abuse.get("status", "missing"),
        "abuse_confidence_score": confidence,
        "total_reports": total_reports,
        "confidence_points": abuse_points,
        "report_volume_points": report_points
    }

    # 3. Intelligence coverage
    successful_sources = int(vt_success) + int(abuse_success)

    # Provider availability is metadata, not threat evidence.
    # Therefore, data quality contributes zero risk points.
    factors["data_quality"] = {
        "successful_sources": successful_sources,
        "total_sources": 2,
        "coverage": (
            "Complete" if successful_sources == 2
            else "Partial" if successful_sources == 1
            else "Unavailable"
        ),
        "points": 0
    }

    if successful_sources < 2:
        reasons.append("Threat intelligence coverage is incomplete.")

    # 4. Calculate threat intelligence score
    total_score = (
        vt_points
        + abuse_points
        + report_points
    )

    factors["total_intelligence_points"] = total_score

    return {
        "ip": ip_data.get("ip"),
        "risk_score": total_score,
        "risk_level": get_risk_level(total_score),
        "factors": factors,
        "reasons": reasons
    }


def get_risk_level(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    return "Low"


def get_recommendation(risk_level):
    recommendations = {
        "Critical": "Immediate investigation and escalation.",
        "High": "Prioritize investigation and validate activity.",
        "Medium": "Manual investigation and contextual validation.",
        "Low": "Continue monitoring and retain evidence."
    }

    return recommendations[risk_level]


def main():
    print("Starting SOC Risk Scoring Engine...")

    alert = load_json(ALERT_FILE)
    enrichment = load_json(ENRICHMENT_FILE)

    severity = alert.get("severity", "").lower()

    if severity not in SEVERITY_POINTS:
        raise ValueError(
            f"Unsupported alert severity: {severity}"
        )

    severity_points = SEVERITY_POINTS[severity]

    ip_assessments = []

    for ip_data in enrichment.get("ip_enrichment", []):
        print(f"Assessing IP: {ip_data.get('ip')}")

        assessment = assess_ip(ip_data)

        assessment["alert_severity"] = severity.title()
        assessment["severity_points"] = severity_points

        final_score = min(
            100,
            severity_points + assessment["risk_score"]
        )

        assessment["risk_score"] = final_score
        assessment["risk_level"] = get_risk_level(final_score)
        assessment["recommended_action"] = get_recommendation(
            assessment["risk_level"]
        )

        ip_assessments.append(assessment)

    # Use the highest IP score as the overall alert score.
    # Do not add multiple IP scores together.
    if ip_assessments:
        highest = max(
            ip_assessments,
            key=lambda item: item["risk_score"]
        )

        overall_score = highest["risk_score"]
    else:
        overall_score = severity_points

    overall_level = get_risk_level(overall_score)

    result = {
        "alert_id": alert.get("alert_id"),
        "assessment_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "alert_severity": severity.title(),
        "severity_points": severity_points,
        "overall_risk_score": overall_score,
        "overall_risk_level": overall_level,
        "recommended_action": get_recommendation(overall_level),
        "ip_assessments": ip_assessments,
        "scoring_note": (
            "Rule-based triage score. Threat intelligence coverage "
            "does not contribute risk points. This is not a probability "
            "of compromise or an automated blocking decision."
        )
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print("\nRisk assessment completed.")
    print(f"Overall risk score: {overall_score}/100")
    print(f"Risk level: {overall_level}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"Processing error: {error}")
        sys.exit(1)
