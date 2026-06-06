#!/usr/bin/env python3
"""
MLOps Phase 2: Register AIRS-approved models to HuggingFace.

Called after a successful AIRS scan. Updates the model card on HuggingFace
to mark the model as AIRS-approved with a timestamp and scan metadata.

Usage:
    python push_to_registry.py models/my-model.yaml [models/another.yaml ...]
    python push_to_registry.py          # processes all *.yaml in models/
"""

import glob
import os
import sys
from datetime import datetime, timezone

import yaml

try:
    from huggingface_hub import HfApi, metadata_update, login
except ImportError:
    print("ERROR: huggingface_hub not installed. Run: pip install huggingface_hub")
    sys.exit(1)

HF_TOKEN = os.environ.get("HF_TOKEN", "")
if not HF_TOKEN:
    print("ERROR: HF_TOKEN env var is required.")
    sys.exit(1)

login(token=HF_TOKEN, add_to_git_credential=False)

DIVIDER = "=" * 62

APPROVAL_BADGE = """
---

## ✅ Prisma AIRS Security Approval

| Field | Value |
|---|---|
| **Status** | APPROVED |
| **Scanned by** | Prisma AIRS Model Security |
| **Scan date** | {scan_date} |
| **Pipeline** | GitHub Actions — AIRS Model Security Gate |
| **Policy** | Passed all security rules |

*This model was automatically scanned and approved by [Prisma AIRS](https://www.paloaltonetworks.com/sase/ai-security) before deployment.*
"""


def register_model(api: HfApi, config_file: str) -> bool:
    with open(config_file) as f:
        config = yaml.safe_load(f)

    name = config.get("name", os.path.basename(config_file))
    uri = config.get("uri", "")

    if not uri or "huggingface.co/" not in uri:
        print(f"  SKIP: {name} — URI is not a HuggingFace repo ({uri})")
        return True

    repo_id = uri.split("huggingface.co/")[-1].rstrip("/")
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n{DIVIDER}")
    print(f"  Model:   {name}")
    print(f"  Repo:    {repo_id}")
    print(f"  Action:  Tagging as AIRS-approved on HuggingFace")
    print(DIVIDER)

    try:
        # Add airs-approved tag to model card metadata
        metadata_update(repo_id=repo_id, metadata={"tags": ["airs-approved"]}, token=HF_TOKEN, overwrite=False)
        print(f"  Tagged:  airs-approved")

        # Append approval block to model card README
        try:
            readme = api.model_info(repo_id=repo_id, token=HF_TOKEN)
            current_card = api.model_info(repo_id=repo_id, token=HF_TOKEN).card_data
        except Exception:
            current_card = None

        approval_text = APPROVAL_BADGE.format(scan_date=scan_date)

        try:
            existing = api.hf_hub_download(
                repo_id=repo_id, filename="README.md", token=HF_TOKEN
            )
            with open(existing) as f:
                readme_content = f.read()

            # Remove any previous approval block to avoid duplication
            if "## ✅ Prisma AIRS Security Approval" in readme_content:
                readme_content = readme_content.split("## ✅ Prisma AIRS Security Approval")[0].rstrip()

            updated_readme = readme_content + "\n" + approval_text
        except Exception:
            updated_readme = f"# {name}\n{approval_text}"

        api.upload_file(
            path_or_fileobj=updated_readme.encode(),
            path_in_repo="README.md",
            repo_id=repo_id,
            token=HF_TOKEN,
            commit_message=f"chore: AIRS security approval [{scan_date}]",
        )
        print(f"  Updated: README.md with AIRS approval block")
        print(f"\n  >> REGISTERED to HuggingFace registry\n")
        return True

    except Exception as e:
        print(f"  ERROR: Failed to register {repo_id}: {e}")
        return False


def main():
    config_files = sys.argv[1:] if len(sys.argv) > 1 else (
        glob.glob("models/*.yaml") + glob.glob("models/*.yml")
    )
    config_files = [f for f in config_files if f.endswith((".yaml", ".yml"))]

    if not config_files:
        print("No model config files to register. Nothing to do.")
        sys.exit(0)

    print(f"\n{DIVIDER}")
    print(f"  MLOps Registry: Registering {len(config_files)} AIRS-approved model(s)")
    print(DIVIDER)

    api = HfApi()
    results: dict[str, bool] = {}

    for config_file in config_files:
        if not os.path.exists(config_file):
            print(f"WARNING: {config_file} not found — skipping")
            continue
        try:
            results[config_file] = register_model(api, config_file)
        except Exception as e:
            print(f"ERROR processing {config_file}: {e}")
            results[config_file] = False

    print(f"\n{DIVIDER}")
    print("  REGISTRATION SUMMARY")
    print(DIVIDER)
    for path, ok in results.items():
        status = "REGISTERED" if ok else "FAILED    "
        print(f"  [{status}]  {path}")
    print(DIVIDER)

    failed = [f for f, ok in results.items() if not ok]
    if failed:
        print(f"\n  {len(failed)} model(s) failed registration.\n")
        sys.exit(1)
    else:
        print(f"\n  All {len(results)} model(s) successfully registered.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
