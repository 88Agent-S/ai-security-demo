from model_security_client.api import ModelSecurityAPIClient
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    client = ModelSecurityAPIClient(base_url=os.getenv("MODEL_SECURITY_API_ENDPOINT"))
    group_uuid = os.getenv("MODEL_SECURITY_GROUP_UUID")
    base = os.path.join(os.path.dirname(__file__), "demo_models")

    models = [
        ("clean-model",    os.path.join(base, "clean-model"),    {"demo": "clean",          "platform": "macmini"}),
        ("pickle-exploit", os.path.join(base, "pickle-exploit"), {"demo": "pickle-exploit", "platform": "macmini"}),
        ("poisoned-model", os.path.join(base, "poisoned-model"), {"demo": "poisoned",       "platform": "macmini"}),
    ]

    for name, path, labels in models:
        print(f"Scanning {name}...")
        result = client.scan(
            security_group_uuid=group_uuid,
            model_path=path,
            labels=labels,
        )
        if result:
            print(f"  outcome:      {result.eval_outcome}")
            print(f"  rules failed: {result.eval_summary.rules_failed}/{result.eval_summary.total_rules}")
            print(f"  formats:      {result.model_formats}")
            print(f"  files:        {result.total_files_scanned}")
        else:
            print("  no result returned")
        print()

    print("Done.")
