# SOC Alert Enrichment & Investigation Automation

A Python-based Blue Team automation project that processes security alerts, extracts indicators, enriches eligible public IP addresses with threat intelligence, calculates risk scores, and generates investigation reports.

## Project Overview

Security Operations Center (SOC) analysts spend considerable time manually collecting indicator information, checking threat intelligence sources, assessing risk, and preparing investigation reports.

This project automates these repetitive investigation steps through a modular Python pipeline.

## Architecture

```text
             Sample Security Alert
                       |
                       v
                Alert Ingestion
                       |
                       v
                 IOC Extraction
                       |
                       v
              Threat Intelligence
                /             \
          VirusTotal        AbuseIPDB
                \             /
                       |
                       v
                  Risk Scoring
                       |
                       v
              Investigation Report
                 /           \
               JSON          HTML
```

## Key Features

- **Alert ingestion:** Validates and normalizes incoming security alerts.
- **IOC extraction:** Extracts IP addresses, URLs, domains, and file hashes.
- **Threat intelligence enrichment:** Queries VirusTotal and AbuseIPDB for eligible public IP addresses.
- **Risk assessment:** Calculates transparent heuristic risk scores using alert severity and available threat intelligence.
- **Automated reporting:** Generates JSON and HTML investigation reports.
- **Pipeline orchestration:** Executes processing stages sequentially and validates their outputs.
- **Logging and error handling:** Records execution details and stops processing when a stage fails.
- **Offline testing:** Supports mock threat intelligence responses without external API requests.
- **Automated testing:** Includes unit, integration, and full-pipeline tests.

## Technology Stack

- Python 3.14.10 (tested)
- REST APIs
- VirusTotal API
- AbuseIPDB API
- Requests
- Python-dotenv
- Pytest
- HTML and CSS
- Git

## Project Structure

```text
SOC-Alert-Enrichment/
├── input/
│   └── sample_alert.json
├── output/
│   └── .gitkeep
├── src/
│   ├── __init__.py
│   ├── alert_ingestion.py
│   ├── ioc_extractor.py
│   ├── threat_intel.py
│   ├── risk_scoring.py
│   ├── report_generator.py
│   └── main.py
├── tests/
│   ├── test_risk_scoring.py
│   ├── test_risk_scoring_integration.py
│   └── test_full_pipeline.py
├── logs/
│   └── .gitkeep
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```powershell
git clone YOUR_GITHUB_REPOSITORY_URL
cd SOC-Alert-Enrichment
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Install dependencies:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Configuration

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Add your own API credentials to `.env`:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SOC_TEST_MODE=0
```

Never commit `.env` or expose API credentials in source code.

## Running the Project

Execute the complete pipeline:

```powershell
.venv\Scripts\python.exe src\main.py
```

The pipeline executes five stages:

1. Alert ingestion and normalization.
2. IOC extraction.
3. Threat intelligence enrichment.
4. Risk assessment.
5. Investigation report generation.

Generated reports are written to the local `output/` directory.

## Offline Testing

The project supports mock threat intelligence responses.

Set the following variable in `.env`:

```env
SOC_TEST_MODE=1
```

Then execute:

```powershell
.venv\Scripts\python.exe src\main.py
```

This runs the pipeline without making external threat intelligence API requests.

## Running Tests

Execute the complete test suite:

```powershell
.venv\Scripts\python.exe -m pytest -v
```

The current test suite contains 23 tests covering risk scoring, integration workflows, and full-pipeline execution.

## Risk Scoring Methodology

The current scoring model uses:

- Alert severity.
- VirusTotal malicious detection counts.
- AbuseIPDB confidence scores.
- Historical report volume, subject to a confidence threshold.

Threat intelligence provider availability is tracked separately as coverage metadata and contributes zero risk points. Missing intelligence data does not artificially increase or decrease the risk score.

Risk levels:

| Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

The model is a rule-based triage heuristic, not a statistically calibrated probability of compromise. Scores should support investigation and analyst decision-making, not replace analyst judgment.

## Security Considerations

- API credentials are stored in environment variables.
- Local environment files are excluded through `.gitignore`.
- Only eligible public IP addresses are submitted for external enrichment.
- Mock mode supports offline testing.
- External threat intelligence queries may disclose queried indicators to third-party providers. Do not submit confidential indicators without authorization.

## Current Limitations

- The current implementation processes JSON-based sample alerts.
- IOC extraction uses pattern-based parsing.
- Threat intelligence enrichment currently focuses on public IP addresses.
- Risk scoring uses a heuristic model.
- The project does not automatically isolate endpoints, block IP addresses, or execute containment actions.

## Future Enhancements

- Microsoft Sentinel and Microsoft Graph integration.
- SIEM alert ingestion through APIs.
- Phishing email investigation automation.
- SQLite-based investigation history.
- FastAPI service layer.
- Streamlit analyst dashboard.
- MITRE ATT&CK mapping.
- Detection engineering and automated response workflows.

## Disclaimer

This project is intended for educational, laboratory, and portfolio demonstration purposes. It is not a production-ready SOAR platform.

## Author

Cybersecurity | Blue Team | SOC Automation | Threat Intelligence