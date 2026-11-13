
import subprocess
import sys
import logging
import time

from pathlib import Path
from datetime import datetime


# ============================================================
# 1. PROJECT CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "pipeline.log"


# ============================================================
# 2. CENTRALIZED LOGGING CONFIGURATION
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ],
    force=True
)

logger = logging.getLogger("SOC-Automation")


# ============================================================
# 3. PIPELINE CONFIGURATION
# ============================================================

PIPELINE = [
    {
        "name": "Alert Ingestion",
        "script": "alert_ingestion.py",
        "expected": ["output/normalized_alert.json"]
    },
    {
        "name": "IOC Extraction",
        "script": "ioc_extractor.py",
        "expected": ["output/extracted_iocs.json"]
    },
    {
        "name": "Threat Intelligence Enrichment",
        "script": "threat_intel.py",
        "expected": ["output/enriched_iocs.json"]
    },
    {
        "name": "Risk Scoring",
        "script": "risk_scoring.py",
        "expected": ["output/risk_assessment.json"]
    },
    {
        "name": "Investigation Report Generation",
        "script": "report_generator.py",
        "expected": [
            "output/investigation_report.json",
            "output/investigation_report.html"
        ]
    }
]


# ============================================================
# 4. PIPELINE STAGE EXECUTION
# ============================================================

def run_stage(stage, number, total):

    print("\n" + "=" * 60)
    print(f"STAGE {number}/{total}: {stage['name']}")
    print("=" * 60)

    logger.info("Starting stage: %s", stage["name"])

    script_path = SRC_DIR / stage["script"]

    # Verify script exists
    if not script_path.is_file():
        logger.error("Script not found: %s", script_path)

        raise FileNotFoundError(
            f"Required script not found: {script_path}"
        )

    # --------------------------------------------------------
    # Capture existing output file state before execution
    # --------------------------------------------------------

    previous_outputs = {}

    for relative_path in stage["expected"]:

        output_file = BASE_DIR / relative_path

        if output_file.exists():

            stat = output_file.stat()

            previous_outputs[relative_path] = {
                "mtime_ns": stat.st_mtime_ns,
                "size": stat.st_size
            }

        else:
            previous_outputs[relative_path] = None

    # --------------------------------------------------------
    # Execute individual Python module
    # --------------------------------------------------------

    stage_start_time = time.perf_counter()

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=BASE_DIR,
        capture_output=True,
        text=True
    )

    # Display script output
    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("Error output:")
        print(result.stderr)

    # --------------------------------------------------------
    # Check execution status
    # --------------------------------------------------------

    if result.returncode != 0:

        logger.error(
            "Stage failed: %s | Exit code: %s",
            stage["name"],
            result.returncode
        )

        raise RuntimeError(
            f"{stage['name']} failed with exit code "
            f"{result.returncode}"
        )

    # --------------------------------------------------------
    # Validate expected output files
    # --------------------------------------------------------

    for relative_path in stage["expected"]:

        output_file = BASE_DIR / relative_path

        # Check whether output exists
        if not output_file.exists():

            logger.error(
                "Expected output missing: %s",
                output_file
            )

            raise FileNotFoundError(
                f"Expected output was not generated: {output_file}"
            )

        # Check whether output is a regular file
        if not output_file.is_file():

            raise RuntimeError(
                f"Expected output is not a regular file: {output_file}"
            )

        # Check whether output is empty
        current_stat = output_file.stat()

        if current_stat.st_size == 0:

            raise RuntimeError(
                f"Expected output file is empty: {output_file}"
            )

        # ----------------------------------------------------
        # Verify output was created or modified
        # ----------------------------------------------------

        previous_state = previous_outputs[relative_path]

        if previous_state is not None:

            unchanged = (
                current_stat.st_mtime_ns
                == previous_state["mtime_ns"]
                and current_stat.st_size
                == previous_state["size"]
            )

            if unchanged:

                logger.error(
                    "Output was not updated: %s",
                    output_file
                )

                raise RuntimeError(
                    f"Output was not updated by this stage: "
                    f"{output_file}"
                )

    # --------------------------------------------------------
    # Calculate execution duration
    # --------------------------------------------------------

    duration = time.perf_counter() - stage_start_time

    print(f"[SUCCESS] {stage['name']} completed.")

    logger.info(
        "Stage completed: %s | Duration: %.2f seconds",
        stage["name"],
        duration
    )

    return True


# ============================================================
# 5. MAIN PIPELINE CONTROLLER
# ============================================================

def main():

    start_time = datetime.now()
    pipeline_start = time.perf_counter()

    completed_stages = 0
    total_stages = len(PIPELINE)

    print("=" * 60)
    print("          BLUE TEAM AUTOMATION LAB")
    print("          SOC ALERT ENRICHMENT PIPELINE")
    print("=" * 60)

    print(f"Project directory: {BASE_DIR}")
    print(f"Execution started: {start_time}")

    logger.info("SOC pipeline execution started")

    try:

        # Execute stages sequentially
        for index, stage in enumerate(PIPELINE, start=1):

            run_stage(stage, index, total_stages)

            completed_stages += 1

        # ----------------------------------------------------
        # Successful pipeline completion
        # ----------------------------------------------------

        end_time = datetime.now()

        duration = time.perf_counter() - pipeline_start

        print("\n" + "=" * 60)
        print("SOC AUTOMATION PIPELINE COMPLETED")
        print("=" * 60)

        print(
            f"Completed stages: "
            f"{completed_stages}/{total_stages}"
        )

        print(f"Execution duration: {duration:.2f} seconds")

        print("\nGenerated reports:")

        print(OUTPUT_DIR / "investigation_report.json")
        print(OUTPUT_DIR / "investigation_report.html")

        logger.info(
            "SOC pipeline execution completed successfully"
        )

        logger.info(
            "Total stages completed: %s/%s",
            completed_stages,
            total_stages
        )

        logger.info(
            "Total execution duration: %.2f seconds",
            duration
        )

    except Exception as error:

        # ----------------------------------------------------
        # Pipeline failure handling
        # ----------------------------------------------------

        logger.exception(
            "SOC pipeline execution failed"
        )

        print("\n" + "=" * 60)
        print("SOC AUTOMATION PIPELINE FAILED")
        print("=" * 60)

        print(
            f"Completed stages: "
            f"{completed_stages}/{total_stages}"
        )

        print(f"Failure reason: {error}")

        sys.exit(1)


# ============================================================
# 6. APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
