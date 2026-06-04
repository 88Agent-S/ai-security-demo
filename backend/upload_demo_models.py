"""
Upload demo models to HuggingFace and scan them via AIRS.
Creates two repos:
  - 88AgentS/ai-security-demo-clean    → safetensors only → ALLOWED
  - 88AgentS/ai-security-demo-poisoned → safetensors + hidden pickle → BLOCKED
"""

import os
from dotenv import load_dotenv
from huggingface_hub import HfApi, create_repo

load_dotenv()

HF_TOKEN = os.getenv("HF_TOKEN")
USERNAME = "88AgentS"

api = HfApi(token=HF_TOKEN)

REPOS = [
    {
        "id": f"{USERNAME}/ai-security-demo-clean",
        "local": "demo_models/clean-model",
        "desc": "Clean classifier model — AI Security Demo (Prisma AIRS)",
    },
    {
        "id": f"{USERNAME}/ai-security-demo-poisoned",
        "local": "demo_models/poisoned-model",
        "desc": "Fine-tuned classifier model — AI Security Demo (Prisma AIRS)",
    },
]

if __name__ == "__main__":
    for repo in REPOS:
        print(f"\nCreating repo: {repo['id']}")
        try:
            create_repo(
                repo_id=repo["id"],
                token=HF_TOKEN,
                repo_type="model",
                exist_ok=True,
                private=False,
            )
            print("  Repo ready.")
        except Exception as e:
            print(f"  Repo create error: {e}")

        print(f"  Uploading files from {repo['local']}...")
        try:
            api.upload_folder(
                folder_path=repo["local"],
                repo_id=repo["id"],
                repo_type="model",
                commit_message="Add demo model files",
            )
            print(f"  Uploaded. → https://huggingface.co/{repo['id']}")
        except Exception as e:
            print(f"  Upload error: {e}")

    print("\nDone.")
