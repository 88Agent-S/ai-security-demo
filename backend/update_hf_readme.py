import os
from dotenv import load_dotenv
from huggingface_hub import HfApi

load_dotenv()
api = HfApi(token=os.getenv("HF_TOKEN"))

for repo_id, path in [
    ("88AgentS/ai-security-demo-clean",    "demo_models/clean-model/README.md"),
    ("88AgentS/ai-security-demo-poisoned", "demo_models/poisoned-model/README.md"),
]:
    api.upload_file(
        path_or_fileobj=path,
        path_in_repo="README.md",
        repo_id=repo_id,
        repo_type="model",
        commit_message="Add license metadata",
    )
    print(f"Updated {repo_id}")
