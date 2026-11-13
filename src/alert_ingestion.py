
import json
import ipaddress
from pathlib import Path


# Find the project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Define input and output files
INPUT_FILE = BASE_DIR / "input" / "sample_alert.json"
OUTPUT_FILE = BASE_DIR / "output" / "normalized_alert.json"


def load_alert():
    """Read the original SOC alert."""

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        alert = json.load(file)

    return alert


def validate_ip(ip_address):
    """Validate an IP address."""

    try:
        ip = ipaddress.ip_address(ip_address)

        return {
            "valid": True,
            "version": ip.version,
            "is_global": ip.is_global
        }

    except ValueError:
        return {
            "valid": False,
            "version": None,
            "is_global": False
        }


def normalize_alert(alert):
    """Standardize the SOC alert."""

    required_fields = [
        "alert_id",
        "source_ip",
        "destination_ip",
        "severity",
        "description"
    ]

    # Check mandatory fields
    for field in required_fields:
        if not alert.get(field):
            raise ValueError(f"Missing required field: {field}")

    # Validate both IP addresses
    source_validation = validate_ip(alert["source_ip"])
    destination_validation = validate_ip(
        alert["destination_ip"]
    )

    if not source_validation["valid"]:
        raise ValueError("Invalid source IP address")

    if not destination_validation["valid"]:
        raise ValueError("Invalid destination IP address")

    # Create standardized output
    normalized = {
        "alert_id": alert["alert_id"],
        "alert_name": alert.get("alert_name", "Unknown"),
        "source_ip": alert["source_ip"],
        "destination_ip": alert["destination_ip"],
        "username": alert.get("username", "Unknown"),
        "hostname": alert.get("hostname", "Unknown"),
        "severity": alert["severity"].lower(),
        "description": alert["description"],
        "detection_source": alert.get(
            "detection_source", "Unknown"
        ),
        "source_ip_validation": source_validation,
        "destination_ip_validation": destination_validation,
        "processing_status": "normalized"
    }

    return normalized


def save_alert(alert):
    """Save normalized alert as JSON."""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alert, file, indent=4)

    print(f"\nNormalized alert saved: {OUTPUT_FILE}")


def main():

    print("Starting SOC Alert Ingestion Engine...")

    try:
        alert = load_alert()

        print("Alert successfully loaded.")

        normalized_alert = normalize_alert(alert)

        print("Alert validation successful.")

        save_alert(normalized_alert)

        print("\nSOC Alert Ingestion completed.")

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"\nProcessing failed: {error}")


if __name__ == "__main__":
    main()
