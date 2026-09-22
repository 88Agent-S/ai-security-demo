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
import time

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

# The demo panel in the UI keys its threat write-ups off these short names, and
# filters scans by `platform`. Tag every scan so pipeline runs show up there too.
DEMO_MODEL_NAMES = {
    "ai-security-demo-clean": "clean",
    "ai-security-demo-poisoned": "poisoned",
    "ai-security-demo-pickle": "pickle-exploit",
}


def demo_labels(uri: str) -> dict:
    """Labels that let the demo UI recognise and name this scan."""
    labels = {
        "platform": "macmini-hf",
        "source": "huggingface" if "huggingface.co" in uri else "local",
    }
    demo = DEMO_MODEL_NAMES.get(uri.rstrip("/").split("/")[-1])
    if demo:
        labels["demo"] = demo
    return labels


BLOCKED_OUTCOMES = {"BLOCKED", "FAIL", "FAILED", "DENY"}

# Transient AIRS responses that mean "the scan isn't finished yet" — NOT a security
# verdict. AIRS pulls the model files asynchronously; if we ask for the result before
# it has retrieved them it returns this and asks us to retry.
TRANSIENT_PATTERNS = (
    "pending scan data retrieval",
    "please retry",
    "retry this request later",
)
SCAN_RETRIES = 4
SCAN_RETRY_WAIT_SECS = 30


def is_transient_error(err: Exception) -> bool:
    msg = str(err).lower()
    return any(p in msg for p in TRANSIENT_PATTERNS)


def run_scan(client: "ModelSecurityAPIClient", **kwargs):
    """client.scan() with retries on transient 'files still being retrieved' errors.

    Re-raises the underlying error if it is not transient, or once retries are
    exhausted (the caller then fails closed)."""
    for attempt in range(1, SCAN_RETRIES + 1):
        try:
            return client.scan(**kwargs)
        except Exception as e:
            if not is_transient_error(e) or attempt == SCAN_RETRIES:
                raise
            print(f"  Scan not ready yet (attempt {attempt}/{SCAN_RETRIES}): {e}")
            print(f"  AIRS is still retrieving the model files — retrying in {SCAN_RETRY_WAIT_SECS}s...")
            time.sleep(SCAN_RETRY_WAIT_SECS)

DIVIDER = "=" * 62

LABEL_SAFE = re.compile(r"[^a-zA-Z0-9_-]")


def sanitize_labels(labels: dict) -> dict:
    """Replace any characters not allowed by LabelSchema with a dash."""
    return {k: LABEL_SAFE.sub("-", str(v)) for k, v in labels.items()}


def print_violations(client: "ModelSecurityAPIClient", scan_uuid) -> None:
    """Print the specific rules that failed, so the CI log shows WHY a model was blocked."""
    try:
        violations = client.get_scan_violations(scan_uuid).violations
    except Exception as e:
        print(f"  (could not retrieve violation detail: {e})")
        return
    if not violations:
        return
    print("\n  Why blocked:")
    for v in violations:
        print(f"    ✗ {v.rule_name}")
        if getattr(v, "description", None):
            print(f"        {v.description}")
        if getattr(v, "file", None):
            print(f"        file:   {v.file}")
        if getattr(v, "threat_description", None):
            print(f"        threat: {v.threat_description}")


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
    labels["pipeline"] = "mlops-pipeline"
    labels["config"] = os.path.basename(config_file)
    labels.update(demo_labels(uri))
    labels = sanitize_labels(labels)

    print(f"\n{DIVIDER}")
    print(f"  Model:  {name}")
    print(f"  URI:    {uri}")
    print(f"  Config: {config_file}")
    print(DIVIDER)
    print("  Submitting to Prisma AIRS... (this may take a few minutes)")

    group_uuid = pick_group_uuid(uri)
    print(f"  Group:  {group_uuid}")

    result = run_scan(
        client,
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

    print_violations(client, result.uuid)

    passed = outcome not in BLOCKED_OUTCOMES
    gate_result = "ALLOWED — model approved for deployment" if passed else "BLOCKED — model rejected by security policy"
    print(f"\n  >> PIPELINE GATE: {gate_result}\n")

    return passed


def scan_uri(client: "ModelSecurityAPIClient", uri: str) -> bool:
    """Scan a raw HuggingFace URI directly (no config file needed)."""
    repo_name = uri.rstrip("/").split("/")[-1]
    labels = sanitize_labels(
        {"pipeline": "mlops-pipeline", "mode": "direct-uri", **demo_labels(uri)}
    )

    print(f"\n{DIVIDER}")
    print(f"  Model:  {repo_name}")
    print(f"  URI:    {uri}")
    print(DIVIDER)
    print("  Submitting to Prisma AIRS... (this may take a few minutes)")

    group_uuid = pick_group_uuid(uri)
    print(f"  Group:  {group_uuid}")

    result = run_scan(
        client,
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

    print_violations(client, result.uuid)

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
            status = "ALLOWED" if scan_uri(client, args.uri) else "BLOCKED"
        except Exception as e:
            print(f"ERROR scanning {args.uri}: {e}")
            status = "ERROR"

        print(f"\n{DIVIDER}")
        print("  SCAN SUMMARY")
        print(DIVIDER)
        print(f"  [{status:7s}]  {args.uri}")
        print(DIVIDER)

        if status == "ALLOWED":
            print(f"\n  PIPELINE PASSED: model approved by Prisma AIRS\n")
            sys.exit(0)
        elif status == "BLOCKED":
            print(f"\n  PIPELINE FAILED: model BLOCKED by Prisma AIRS security policy\n")
            sys.exit(1)
        else:
            print(f"\n  PIPELINE FAILED (fail-closed): scan could not complete "
                  f"(transient error after {SCAN_RETRIES} retries) — NOT a policy block\n")
            sys.exit(1)

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

    results: dict[str, str] = {}
    for config_file in config_files:
        if not os.path.exists(config_file):
            print(f"WARNING: {config_file} not found — skipping")
            continue
        try:
            results[config_file] = "ALLOWED" if scan_model(client, config_file) else "BLOCKED"
        except Exception as e:
            print(f"ERROR scanning {config_file}: {e}")
            results[config_file] = "ERROR"

    print(f"\n{DIVIDER}")
    print("  SCAN SUMMARY")
    print(DIVIDER)
    for path, status in results.items():
        print(f"  [{status:7s}]  {path}")
    print(DIVIDER)

    blocked = [f for f, s in results.items() if s == "BLOCKED"]
    errored = [f for f, s in results.items() if s == "ERROR"]
    if blocked or errored:
        if blocked:
            print(f"\n  PIPELINE FAILED: {len(blocked)} model(s) BLOCKED by Prisma AIRS security policy")
        if errored:
            print(f"\n  PIPELINE FAILED (fail-closed): {len(errored)} model(s) could not be scanned "
                  f"(transient error after {SCAN_RETRIES} retries) — this is NOT a policy block")
        print()
        sys.exit(1)
    else:
        print(f"\n  PIPELINE PASSED: All {len(results)} model(s) approved by Prisma AIRS\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
