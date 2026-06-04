"""
Scan HuggingFace-hosted demo models via AIRS and tag with platform=macmini-hf
so the demo panel shows them alongside (or instead of) local scans.
"""

import os
from dotenv import load_dotenv
from model_security_client.api import ModelSecurityAPIClient

load_dotenv()

os.environ.setdefault("TSG_ID", os.getenv("MODEL_SECURITY_TSG_ID", ""))

HF_GROUP_UUID = "f9b755b6-879e-468b-8de6-74e8f00f5650"  # Default HUGGING_FACE group

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
