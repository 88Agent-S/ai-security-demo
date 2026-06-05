#!/usr/bin/env python3
"""
AIRS Model Security Gate — CI entry point.

Reads model config YAML files, submits each to Prisma AIRS for scanning,
and exits non-zero if any model is BLOCKED.

Usage:
    python ci_scan_model.py models/my-model.yaml [models/another.yaml ...]
    python ci_scan_model.py --uri https://huggingface.co/org/repo
    python ci_scan_model.py          # scans all *.yaml in models/
"""

import argparse
import glob
import os
import re
import sys

import yaml
from dotenv import load_dotenv

load_dotenv()

# Map MODEL_SECURITY_TSG_ID → TSG_ID expected by the SDK
_tsg = os.getenv("MODEL_SECURITY_TSG_ID")
if _tsg:
    os.environ.setdefault("TSG_ID", _tsg)

try:
    from model_security_client.api import ModelSecurityAPIClient
except ImportError:
    print("ERROR: model-security-client not installed.")
    print("  Run: pip install model-security-client --extra-index-url <pypi_url>")
    sys.exit(1)

GROUP_UUID_LOCAL = os.environ.get("MODEL_SECURITY_GROUP_UUID", "")
GROUP_UUID_HF = os.environ.get("MODEL_SECURITY_HF_GROUP_UUID", "")

if not GROUP_UUID_LOCAL and not GROUP_UUID_HF:
    print("ERROR: MODEL_SECURITY_GROUP_UUID or MODEL_SECURITY_HF_GROUP_UUID env var is required.")
    sys.exit(1)

API_ENDPOINT = os.getenv(
    "MODEL_SECURITY_API_ENDPOINT", "https://api.sase.paloaltonetworks.com/aims"
)


def pick_group_uuid(uri: str) -> str:
    """Return the correct security group UUID based on model source type."""
    if "huggingface.co" in uri:
        return GROUP_UUID_HF or GROUP_UUID_LOCAL
    return GROUP_UUID_LOCAL or GROUP_UUID_HF

BLOCKED_OUTCOMES = {"BLOCKED", "FAIL", "FAILED", "DENY"}

DIVIDER = "=" * 62

LABEL_SAFE = re.compile(r"[^a-zA-Z0-9_-]")


def sanitize_labels(labels: dict) -> dict:
    """Replace any characters not allowed by LabelSchema with a dash."""
    return {k: LABEL_SAFE.sub("-", str(v)) for k, v in labels.items()}


def scan_model(client: "ModelSecurityAPIClient", config_file: str) -> bool:
    """Scan one model config. Returns True if ALLOWED, False if BLOCKED."""
    with open(config_file) as f:
        config = yaml.safe_load(f)

    name = config.get("name", os.path.basename(config_file))
    uri = config.get("uri", "")
    if not uri:
        print(f"  ERROR: no 'uri' field in {config_file}")
        return False

    labels = config.get("labels", {})
    labels["source"] = "mlops-pipeline"
    labels["config"] = os.path.basename(config_file)
    labels = sanitize_labels(labels)

    print(f"\n{DIVIDER}")
    print(f"  Model:  {name}")
    print(f"  URI:    {uri}")
    print(f"  Config: {config_file}")
    print(DIVIDER)
    print("  Submitting to Prisma AIRS... (this may take a few minutes)")

    group_uuid = pick_group_uuid(uri)
    print(f"  Group:  {group_uuid}")

    result = client.scan(
        security_group_uuid=group_uuid,
        model_uri=uri,
        labels=labels,
        poll_timeout_secs=600,
        scan_timeout_secs=600,
        poll_interval_secs=15,
    )

    if not result:
        print("  RESULT:       No result returned — treating as BLOCKED")
        print(f"\n  >> PIPELINE GATE: BLOCKED\n")
        return False

    outcome = (result.eval_outcome or "").upper()
    rules_failed = result.eval_summary.rules_failed
    total_rules = result.eval_summary.total_rules
    formats = result.model_formats

    print(f"  Outcome:      {outcome}")
    print(f"  Rules failed: {rules_failed} / {total_rules}")
    print(f"  Formats:      {formats}")

    passed = outcome not in BLOCKED_OUTCOMES
    gate_result = "ALLOWED — model approved for deployment" if passed else "BLOCKED — model rejected by security policy"
    print(f"\n  >> PIPELINE GATE: {gate_result}\n")

    return passed


def scan_uri(client: "ModelSecurityAPIClient", uri: str) -> bool:
    """Scan a raw HuggingFace URI directly (no config file needed)."""
    repo_name = uri.rstrip("/").split("/")[-1]
    labels = sanitize_labels({"source": "mlops-pipeline", "mode": "direct-uri"})

    print(f"\n{DIVIDER}")
    print(f"  Model:  {repo_name}")
    print(f"  URI:    {uri}")
    print(DIVIDER)
    print("  Submitting to Prisma AIRS... (this may take a few minutes)")

    group_uuid = pick_group_uuid(uri)
    print(f"  Group:  {group_uuid}")

    result = client.scan(
        security_group_uuid=group_uuid,
        model_uri=uri,
        labels=labels,
        poll_timeout_secs=600,
        scan_timeout_secs=600,
        poll_interval_secs=15,
    )

    if not result:
        print("  RESULT:       No result returned — treating as BLOCKED")
        print(f"\n  >> PIPELINE GATE: BLOCKED\n")
        return False

    outcome = (result.eval_outcome or "").upper()
    rules_failed = result.eval_summary.rules_failed
    total_rules = result.eval_summary.total_rules
    formats = result.model_formats

    print(f"  Outcome:      {outcome}")
    print(f"  Rules failed: {rules_failed} / {total_rules}")
    print(f"  Formats:      {formats}")

    passed = outcome not in BLOCKED_OUTCOMES
    gate_result = "ALLOWED — model approved for deployment" if passed else "BLOCKED — model rejected by security policy"
    print(f"\n  >> PIPELINE GATE: {gate_result}\n")

    return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", help="Scan a HuggingFace URL directly")
    parser.add_argument("files", nargs="*", help="Model config YAML files to scan")
    args = parser.parse_args()

    client = ModelSecurityAPIClient(base_url=API_ENDPOINT)

    # Direct URI mode
    if args.uri:
        print(f"\n{DIVIDER}")
        print(f"  Prisma AIRS Model Security Gate")
        print(f"  Mode: direct URI scan")
        print(DIVIDER)
        try:
            passed = scan_uri(client, args.uri)
        except Exception as e:
            print(f"ERROR scanning {args.uri}: {e}")
            passed = False

        print(f"\n{DIVIDER}")
        print("  SCAN SUMMARY")
        print(DIVIDER)
        print(f"  [{'ALLOWED' if passed else 'BLOCKED':7s}]  {args.uri}")
        print(DIVIDER)

        if not passed:
            print(f"\n  PIPELINE FAILED: model blocked by Prisma AIRS\n")
            sys.exit(1)
        else:
            print(f"\n  PIPELINE PASSED: model approved by Prisma AIRS\n")
            sys.exit(0)

    # File mode
    config_files = args.files if args.files else (
        glob.glob("models/*.yaml") + glob.glob("models/*.yml")
    )
    config_files = [f for f in config_files if f.endswith((".yaml", ".yml"))]

    if not config_files:
        print("No model config files to scan. Nothing to do.")
        sys.exit(0)

    print(f"\n{DIVIDER}")
    print(f"  Prisma AIRS Model Security Gate")
    print(f"  Scanning {len(config_files)} model(s)")
    print(DIVIDER)

    results: dict[str, bool] = {}
    for config_file in config_files:
        if not os.path.exists(config_file):
            print(f"WARNING: {config_file} not found — skipping")
            continue
        try:
            results[config_file] = scan_model(client, config_file)
        except Exception as e:
            print(f"ERROR scanning {config_file}: {e}")
            results[config_file] = False

    print(f"\n{DIVIDER}")
    print("  SCAN SUMMARY")
    print(DIVIDER)
    for path, passed in results.items():
        icon = "ALLOWED" if passed else "BLOCKED"
        print(f"  [{icon:7s}]  {path}")
    print(DIVIDER)

    blocked = [f for f, ok in results.items() if not ok]
    if blocked:
        print(f"\n  PIPELINE FAILED: {len(blocked)} model(s) blocked by Prisma AIRS\n")
        sys.exit(1)
    else:
        print(f"\n  PIPELINE PASSED: All {len(results)} model(s) approved by Prisma AIRS\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
