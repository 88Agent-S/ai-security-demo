"""
Scan HuggingFace-hosted demo models via AIRS and tag with platform=macmini-hf
so the demo panel shows them alongside (or instead of) local scans.
"""

import os
from dotenv import load_dotenv
from model_security_client.api import ModelSecurityAPIClient

load_dotenv()

os.environ.setdefault("TSG_ID", os.getenv("MODEL_SECURITY_TSG_ID", ""))

# Read from env: this moved when model scanning migrated to the new SCM tenant, and a
# stale hardcoded UUID silently scans against a group that no longer exists.
HF_GROUP_UUID = os.getenv("MODEL_SECURITY_HF_GROUP_UUID") or os.getenv(
    "MODEL_SECURITY_GROUP_UUID", ""
)
if not HF_GROUP_UUID:
    raise SystemExit(
        "ERROR: set MODEL_SECURITY_HF_GROUP_UUID (or MODEL_SECURITY_GROUP_UUID) in .env"
    )

MODELS = [
    {
        "uri": "https://huggingface.co/88AgentS/ai-security-demo-clean",
        "labels": {"demo": "clean", "platform": "macmini-hf", "source": "huggingface"},
    },
    {
        "uri": "https://huggingface.co/88AgentS/ai-security-demo-poisoned",
        "labels": {"demo": "poisoned", "platform": "macmini-hf", "source": "huggingface"},
    },
]

if __name__ == "__main__":
    client = ModelSecurityAPIClient(base_url=os.getenv("MODEL_SECURITY_API_ENDPOINT"))

    for m in MODELS:
        print(f"Scanning {m['uri']} ...")
        result = client.scan(
            security_group_uuid=HF_GROUP_UUID,
            model_uri=m["uri"],
            labels=m["labels"],
            poll_timeout_secs=600,
            scan_timeout_secs=600,
            poll_interval_secs=15,
        )
        if result:
            print(f"  outcome:      {result.eval_outcome}")
            print(f"  rules failed: {result.eval_summary.rules_failed}/{result.eval_summary.total_rules}")
            print(f"  formats:      {result.model_formats}")
        else:
            print("  no result")
        print()

    print("Done.")
