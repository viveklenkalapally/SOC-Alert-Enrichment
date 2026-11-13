
import json
import ipaddress
import os
import sys
import time
import requests

from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "output" / "extracted_iocs.json"
OUTPUT_FILE = BASE_DIR / "output" / "enriched_iocs.json"

load_dotenv(BASE_DIR / ".env")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

TIMEOUT = 15


# ============================================================
# LOAD IOC DATA
# ============================================================

def load_iocs():
    """Load extracted IOCs from JSON."""

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        iocs = json.load(file)

    if not isinstance(iocs, dict):
        raise ValueError("IOC input must be a JSON object.")

    if not iocs.get("alert_id"):
        raise ValueError("IOC input is missing alert_id.")

    if not isinstance(iocs.get("ips", []), list):
        raise ValueError("IOC IP data must be a list.")

    return iocs


# ============================================================
# IP VALIDATION
# ============================================================

def validate_public_ip(ip):
    """Only investigate globally routable IP addresses."""

    try:
        address = ipaddress.ip_address(ip)

        if not address.is_global:
            print(f"Skipping non-global IP: {ip}")
            return False

        return True

    except ValueError:
        print(f"Skipping invalid IP: {ip}")
        return False


# ============================================================
# VIRUSTOTAL ENRICHMENT
# ============================================================

def check_virustotal(ip):
    """Retrieve an IP reputation report from VirusTotal."""

    if not VT_API_KEY:
        return {
            "status": "skipped",
            "reason": "API key missing"
        }

    url = (
        f"https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip}"
    )

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {"status": "not_found"}

        if response.status_code == 429:
            return {"status": "rate_limited"}

        response.raise_for_status()

        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})

        return {
            "status": "success",
            "reputation": data.get("reputation"),
            "analysis_stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
        }

    except requests.exceptions.HTTPError as error:
        return {
            "status": "http_error",
            "details": str(error)
        }

    except requests.exceptions.Timeout:
        return {"status": "timeout"}

    except requests.exceptions.RequestException as error:
        return {
            "status": "connection_error",
            "details": str(error)
        }

    except (ValueError, KeyError, TypeError):
        return {"status": "invalid_response"}


# ============================================================
# ABUSEIPDB ENRICHMENT
# ============================================================

def check_abuseipdb(ip):
    """Retrieve IP abuse reputation from AbuseIPDB."""

    if not ABUSE_API_KEY:
        return {
            "status": "skipped",
            "reason": "API key missing"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )

        if response.status_code == 429:
            return {"status": "rate_limited"}

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "status": "success",
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp")
        }

    except requests.exceptions.HTTPError as error:
        return {
            "status": "http_error",
            "details": str(error)
        }

    except requests.exceptions.Timeout:
        return {"status": "timeout"}

    except requests.exceptions.RequestException as error:
        return {
            "status": "connection_error",
            "details": str(error)
        }

    except (ValueError, KeyError, TypeError):
        return {"status": "invalid_response"}


# ============================================================
# MOCK THREAT INTELLIGENCE
# ============================================================

def get_mock_enrichment(ip):
    """Return deterministic synthetic data for offline testing."""

    print(f"Using mock threat intelligence for: {ip}")

    return {
        "virustotal": {
            "status": "success",
            "reputation": 0,
            "analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
                "undetected": 40
            }
        },
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": "TEST",
            "usage_type": "Test Data",
            "isp": "Mock Provider"
        }
    }


# ============================================================
# IOC ENRICHMENT ENGINE
# ============================================================

def enrich_iocs(iocs, use_mock=False):
    """Enrich extracted IPs using live or mock intelligence."""

    results = []

    global_ips = [
        ip for ip in iocs.get("ips", [])
        if validate_public_ip(ip)
    ]

    for index, ip in enumerate(global_ips):

        print(f"\nInvestigating IP: {ip}")

        if use_mock:

            enrichment = get_mock_enrichment(ip)

            vt_result = enrichment["virustotal"]
            abuse_result = enrichment["abuseipdb"]

        else:

            vt_result = check_virustotal(ip)

            # Respect VirusTotal public API rate limit.
            if (
                index < len(global_ips) - 1
                and VT_API_KEY
            ):
                time.sleep(16)

            abuse_result = check_abuseipdb(ip)

        results.append({
            "ip": ip,
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        })

    return {
        "alert_id": iocs.get("alert_id"),
        "enrichment_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "enrichment_mode": "mock" if use_mock else "live",
        "ip_enrichment": results
    }


# ============================================================
# SAVE ENRICHMENT RESULTS
# ============================================================

def save_results(results):
    """Save enrichment results to JSON."""

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nEnrichment results saved: {OUTPUT_FILE}")


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():

    print("Starting Threat Intelligence Enrichment...")

    use_mock = os.getenv("SOC_TEST_MODE") == "1"

    if use_mock:
        print("OFFLINE TEST MODE ENABLED")
    else:
        print("LIVE THREAT INTELLIGENCE MODE ENABLED")

    try:

        iocs = load_iocs()

        results = enrich_iocs(
            iocs,
            use_mock=use_mock
        )

        save_results(results)

        print("\nThreat intelligence enrichment completed.")

    except (
        OSError,
        json.JSONDecodeError,
        ValueError
    ) as error:

        print(f"Processing error: {error}")
        sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
