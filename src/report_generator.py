print("REPORT GENERATOR FILE LOADED")
import json
import html
from pathlib import Path
from datetime import datetime, timezone
import ipaddress


BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "output" / "normalized_alert.json"
IOC_FILE = BASE_DIR / "output" / "extracted_iocs.json"
ENRICHMENT_FILE = BASE_DIR / "output" / "enriched_iocs.json"
RISK_FILE = BASE_DIR / "output" / "risk_assessment.json"

JSON_OUTPUT = BASE_DIR / "output" / "investigation_report.json"
HTML_OUTPUT = BASE_DIR / "output" / "investigation_report.html"


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def safe_text(value):
    """Escape data before inserting it into HTML."""
    return html.escape(str(value if value is not None else "N/A"))


def classify_ip(ip_value):
    """
    Classify an IP as public, reserved documentation,
    or another non-public/special-use address.
    """

    try:
        ip = ipaddress.ip_address(ip_value)

        # Documentation-only IPv4 ranges (TEST-NET)
        documentation_ranges = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24")
        ]

        if any(ip in network for network in documentation_ranges):
            return "Reserved documentation IP (TEST-NET)"

        if ip.is_global:
            return "Public IP"

        return "Non-public or special-use IP"

    except ValueError:
        return "Invalid IP address"

def build_report(alert, iocs, enrichment, risk):
    ip_assessments = risk.get("ip_assessments", [])

    report = {
        "report_id": f"REPORT-{alert.get('alert_id', 'UNKNOWN')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "alert_summary": {
            "alert_id": alert.get("alert_id"),
            "alert_name": alert.get("alert_name"),
            "severity": alert.get("severity"),
            "detection_source": alert.get("detection_source"),
            "username": alert.get("username"),
            "hostname": alert.get("hostname"),
            "description": alert.get("description")
        },

       "indicators_of_compromise": {
    "ips": [
        {
            "address": ip,
            "classification": classify_ip(ip),
            "external_reputation_checked": any(
                item.get("ip") == ip
                for item in enrichment.get("ip_enrichment", [])
            )
        }
        for ip in iocs.get("ips", [])
    ],
    "domains": iocs.get("domains", []),
    "urls": iocs.get("urls", []),
    "hashes": iocs.get("hashes", {})
},

        "threat_intelligence": enrichment.get(
            "ip_enrichment", []
        ),

        "risk_assessment": {
            "overall_score": risk.get("overall_risk_score"),
            "overall_level": risk.get("overall_risk_level"),
            "recommended_action": risk.get("recommended_action"),
            "ip_assessments": ip_assessments
        },

        "analyst_observations": [
            "Threat intelligence results are external reputation signals.",
            "A vendor detection alone does not confirm malicious activity.",
            "Historical abuse reports require contextual validation.",
            "Correlate network activity with endpoint and identity telemetry."
        ],

        "investigation_checklist": [
            "Validate the source and destination IP addresses.",
            "Review connection timestamps, ports and protocols.",
            "Identify the process responsible for the connection.",
            "Check DNS queries and proxy or firewall logs.",
            "Correlate the activity with endpoint detection telemetry.",
            "Review related alerts for the same user and hostname.",
            "Document findings before closing or escalating the incident."
        ],

        "analyst_conclusion": (
            "Automated assessment completed. Manual investigation "
            "is required before determining whether this activity "
            "represents a security incident."
        ),

        "limitations": [
            "This report uses the available alert and enrichment data only.",
            "Missing intelligence is not evidence of a clean indicator.",
            "The risk score is a triage heuristic, not a probability "
            "of compromise.",
            "No containment or remediation action was performed."
        ]
    }

    return report


def render_list(items):
    if not items:
        return "<li>None identified</li>"

    return "".join(
        f"<li>{safe_text(item)}</li>" for item in items
    )


def render_hashes(hashes):
    if not hashes:
        return "<p>No file hashes identified.</p>"

    sections = []

    for hash_type, values in hashes.items():
        if isinstance(values, list):
            values = ", ".join(str(value) for value in values)

        sections.append(
            f"<p><strong>{safe_text(hash_type)}:</strong> "
            f"{safe_text(values)}</p>"
        )

    return "".join(sections)


def generate_html(report):
    alert = report["alert_summary"]
    risk = report["risk_assessment"]
    iocs = report["indicators_of_compromise"]

    ip_rows = []

    for item in risk["ip_assessments"]:
        factors = item.get("factors", {})
        vt = factors.get("virustotal", {})
        abuse = factors.get("abuseipdb", {})

        ip_rows.append(
            f"""
            <tr>
                <td>{safe_text(item.get('ip'))}</td>
                <td>{safe_text(item.get('risk_score'))}/100</td>
                <td>{safe_text(item.get('risk_level'))}</td>
                <td>{safe_text(vt.get('malicious_detections'))}</td>
                <td>{safe_text(abuse.get('abuse_confidence_score'))}%</td>
            </tr>
            """
        )

    if not ip_rows:
        ip_rows.append(
            "<tr><td colspan='5'>No IP assessments available</td></tr>"
        )

    severity_class = safe_text(
        str(risk.get("overall_level", "unknown")).lower()
    )

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>SOC Investigation Report</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f3f5f8;
                color: #202938;
                margin: 0;
                padding: 30px;
            }}

            .container {{
                max-width: 1050px;
                margin: auto;
                background: white;
                padding: 32px;
                border-radius: 10px;
            }}

            h1, h2 {{
                color: #172b4d;
            }}

            h2 {{
                border-bottom: 1px solid #e5e7eb;
                padding-bottom: 9px;
                margin-top: 30px;
            }}

            .summary {{
                display: flex;
                gap: 20px;
                flex-wrap: wrap;
            }}

            .metric {{
                background: #f3f5f8;
                padding: 18px;
                border-radius: 8px;
                flex: 1;
                min-width: 150px;
            }}

            .metric strong {{
                display: block;
                font-size: 25px;
                margin-top: 8px;
            }}

            .risk {{
                text-transform: uppercase;
                font-weight: bold;
            }}

            .risk.critical {{ color: #b91c1c; }}
            .risk.high {{ color: #c2410c; }}
            .risk.medium {{ color: #a16207; }}
            .risk.low {{ color: #15803d; }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}

            th, td {{
                padding: 12px;
                border: 1px solid #e5e7eb;
                text-align: left;
                overflow-wrap: anywhere;
            }}

            th {{
                background: #f3f5f8;
            }}

            li {{
                margin: 9px 0;
            }}

            .notice {{
                background: #fff7ed;
                padding: 15px;
                border-left: 4px solid #ea580c;
                margin-top: 20px;
            }}

            .footer {{
                margin-top: 35px;
                color: #64748b;
                font-size: 12px;
            }}

            @media print {{
                body {{ background: white; padding: 0; }}
                .container {{ max-width: none; }}
            }}
        </style>
    </head>

    <body>
    <div class="container">

        <h1>SOC Investigation Report</h1>
        <p><strong>Report ID:</strong>
            {safe_text(report.get('report_id'))}</p>
        <p><strong>Generated:</strong>
            {safe_text(report.get('generated_at'))}</p>

        <h2>1. Alert Summary</h2>
        <p><strong>Alert ID:</strong> {safe_text(alert.get('alert_id'))}</p>
        <p><strong>Alert Name:</strong> {safe_text(alert.get('alert_name'))}</p>
        <p><strong>Severity:</strong> {safe_text(alert.get('severity'))}</p>
        <p><strong>Detection Source:</strong> {safe_text(alert.get('detection_source'))}</p>
        <p><strong>Username:</strong> {safe_text(alert.get('username'))}</p>
        <p><strong>Hostname:</strong> {safe_text(alert.get('hostname'))}</p>
        <p><strong>Description:</strong> {safe_text(alert.get('description'))}</p>

        <h2>2. Risk Assessment</h2>

        <div class="summary">
            <div class="metric">
                Risk Score
                <strong>{safe_text(risk.get('overall_score'))}/100</strong>
            </div>

            <div class="metric">
                Risk Level
                <strong class="risk {severity_class}">
                    {safe_text(risk.get('overall_level'))}
                </strong>
            </div>
        </div>

        <p><strong>Recommended Action:</strong>
            {safe_text(risk.get('recommended_action'))}</p>

        <h2>3. Indicators of Compromise</h2>

        <h3>IP Addresses</h3>
        <ul>
{
    "".join(
        f"<li><strong>{safe_text(item['address'])}</strong>"
        f" — {safe_text(item['classification'])}"
        f" — Reputation checked: "
        f"{'Yes' if item['external_reputation_checked'] else 'No'}"
        f"</li>"
        for item in iocs.get("ips", [])
    )
    or "<li>None identified</li>"
}
</ul>

        <h3>Domains</h3>
        <ul>{render_list(iocs.get('domains', []))}</ul>

        <h3>URLs</h3>
        <ul>{render_list(iocs.get('urls', []))}</ul>

        <h3>File Hashes</h3>
        {render_hashes(iocs.get('hashes', {}))}

        <h2>4. IP Risk Details</h2>

        <table>
            <tr>
                <th>IP Address</th>
                <th>Score</th>
                <th>Risk</th>
                <th>VT Malicious</th>
                <th>AbuseIPDB Confidence</th>
            </tr>
            {''.join(ip_rows)}
        </table>

        <h2>5. Analyst Observations</h2>
        <ul>{render_list(report.get('analyst_observations', []))}</ul>

        <h2>6. Investigation Checklist</h2>
        <ul>{render_list(report.get('investigation_checklist', []))}</ul>

        <div class="notice">
            <strong>Analyst Conclusion</strong>
            <p>{safe_text(report.get('analyst_conclusion'))}</p>
        </div>

        <h2>7. Limitations</h2>
        <ul>{render_list(report.get('limitations', []))}</ul>

        <div class="footer">
            Generated automatically by the Blue Team Automation Lab.
            This report requires analyst validation.
        </div>

    </div>
    </body>
    </html>
    """


def main():
    print("Starting SOC Investigation Report Generator...")

    alert = load_json(ALERT_FILE)
    iocs = load_json(IOC_FILE)
    enrichment = load_json(ENRICHMENT_FILE)
    risk = load_json(RISK_FILE)

    # Ensure all files refer to the same alert.
    alert_id = alert.get("alert_id")

    for data in (iocs, enrichment, risk):
        if data.get("alert_id") != alert_id:
            raise ValueError(
                "Alert ID mismatch. Check that all input files "
                "belong to the same alert."
            )

    report = build_report(alert, iocs, enrichment, risk)

    JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with open(JSON_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    html_content = generate_html(report)

    with open(HTML_OUTPUT, "w", encoding="utf-8") as file:
        file.write(html_content)

    print("\nInvestigation report generated successfully.")
    print(f"JSON report: {JSON_OUTPUT}")
    print(f"HTML report: {HTML_OUTPUT}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Report generation error: {error}")