"""Delete everything infra/deploy.py created: harness, gate Lambda, three roles, guardrail."""

import pathlib
import sys
import time

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from warden import config

R = config.REGION
iam = boto3.client("iam")
lam = boto3.client("lambda", region_name=R)
bedrock = boto3.client("bedrock", region_name=R)
acc = boto3.client("bedrock-agentcore-control", region_name=R)


def log(msg):
    print(f"[teardown] {msg}", flush=True)


def main():
    for h in acc.list_harnesses().get("harnesses", []):
        if h["harnessName"] == config.HARNESS_NAME:
            acc.delete_harness(harnessId=h["harnessId"])
            log(f"deleting harness {h['harnessId']}")
            for _ in range(60):
                if not any(
                    x["harnessId"] == h["harnessId"]
                    for x in acc.list_harnesses().get("harnesses", [])
                ):
                    break
                time.sleep(5)
    for fn in ("gate", "scan"):
        try:
            lam.delete_function(FunctionName=f"{config.PREFIX}-{fn}")
            log(f"deleted Lambda {config.PREFIX}-{fn}")
        except lam.exceptions.ResourceNotFoundException:
            pass
    for role in ("gate", "auditor", "harness"):
        name = f"{config.PREFIX}-{role}"
        try:
            for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=name, PolicyName=p)
            iam.delete_role(RoleName=name)
            log(f"deleted role {name}")
        except iam.exceptions.NoSuchEntityException:
            pass
    for g in bedrock.list_guardrails()["guardrails"]:
        if g["name"] == config.PREFIX:
            bedrock.delete_guardrail(guardrailIdentifier=g["id"])
            log(f"deleted guardrail {g['id']}")
    config.STATE_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
