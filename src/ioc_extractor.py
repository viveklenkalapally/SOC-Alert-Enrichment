
import json
import re
import ipaddress
import sys

from pathlib import Path


# Project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Read normalized alert from the previous pipeline stage
INPUT_FILE = BASE_DIR / "output" / "normalized_alert.json"
OUTPUT_FILE = BASE_DIR / "output" / "extracted_iocs.json"


def load_alert():
    """Load and validate the normalized SOC alert."""

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        alert = json.load(file)

    if not isinstance(alert, dict):
        raise ValueError("Normalized alert must be a JSON object.")

    if not alert.get("alert_id"):
        raise ValueError("Normalized alert is missing alert_id.")

    return alert


def extract_ips(text):
    """Extract and validate IPv4 addresses."""

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(pattern, text)

    valid_ips = []

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            valid_ips.append(candidate)
        except ValueError:
            continue

    return sorted(set(valid_ips))


def extract_urls(text):
    """Extract HTTP and HTTPS URLs."""

    pattern = r"https?://[^\s<>\"']+"
    urls = re.findall(pattern, text, re.IGNORECASE)

    urls = [
        url.rstrip(".,;:!?)")
        for url in urls
    ]

    return sorted(set(urls))


def extract_domains(text):
    """Extract domain names."""

    pattern = (
        r"(?<![\w@.-])"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}"
        r"(?![\w.-])"
    )

    domains = re.findall(pattern, text)

    return sorted(set(
        domain.lower() for domain in domains
    ))


def extract_hashes(text):
    """Extract MD5, SHA1 and SHA256 hashes."""

    pattern = (
        r"\b(?:[a-fA-F0-9]{32}|"
        r"[a-fA-F0-9]{40}|"
        r"[a-fA-F0-9]{64})\b"
    )

    candidates = re.findall(pattern, text)

    results = {
        "md5": [],
        "sha1": [],
        "sha256": []
    }

    for value in candidates:
        value = value.lower()

        if len(value) == 32:
            results["md5"].append(value)
        elif len(value) == 40:
            results["sha1"].append(value)
        elif len(value) == 64:
            results["sha256"].append(value)

    return {
        key: sorted(set(values))
        for key, values in results.items()
    }


def extract_iocs(alert):
    """Extract indicators from the normalized alert."""

    text = " ".join(
        str(value)
        for value in alert.values()
        if value is not None
    )

    iocs = {
        "alert_id": alert.get("alert_id"),
        "ips": extract_ips(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "hashes": extract_hashes(text)
    }

    return iocs


def save_iocs(iocs):
    """Save extracted indicators to JSON."""

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(iocs, file, indent=4)

    print(f"\nIOC results saved to: {OUTPUT_FILE}")


def main():

    print("Starting SOC IOC Extraction Engine...")

    try:
        alert = load_alert()

        print("Normalized SOC alert loaded successfully.")

        iocs = extract_iocs(alert)

        save_iocs(iocs)

        print("\nIOC extraction completed.")
        print("\nExtracted indicators:")
        print(json.dumps(iocs, indent=4))

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Processing error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
