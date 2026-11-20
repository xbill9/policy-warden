"""Create or update everything Policy Warden runs on. Safe to re-run.

  1. Bedrock Guardrail (infra/guardrail.json) and a numbered version
  2. Gate Lambda (hooks/gate.py) with a role that can only apply that guardrail
  3. Auditor role: the read-only identity every scan runs under
  4. Harness execution role: one model, one Lambda, explicit deny on account APIs
  5. AgentCore Harness with four inline tools, an allowlist, three Lambda hooks
     and execution limits

Writes ARNs to .warden.json.
"""

import io
import json
import pathlib
import string
import sys
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from warden import config
from warden.tools import TOOL_NAMES, harness_tools

ROOT = config.ROOT
R = config.REGION
iam = boto3.client("iam")
lam = boto3.client("lambda", region_name=R)
bedrock = boto3.client("bedrock", region_name=R)
acc = boto3.client("bedrock-agentcore-control", region_name=R)
ACCOUNT = boto3.client("sts").get_caller_identity()["Account"]

GATE_FN = f"{config.PREFIX}-gate"
GATE_ROLE = f"{config.PREFIX}-gate"
AUDITOR_ROLE = f"{config.PREFIX}-auditor"
HARNESS_ROLE = f"{config.PREFIX}-harness"


def log(msg):
    print(f"[deploy] {msg}", flush=True)


def fill(path, **values):
    text = (ROOT / path).read_text()
    return json.loads(
        string.Template(text).substitute(REGION=R, ACCOUNT=ACCOUNT, **values)
    )


def ensure_role(name, trust, policy):
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Policy Warden",
            Tags=[{"Key": "app", "Value": config.PREFIX}],
        )["Role"]["Arn"]
        log(f"created role {name}")
    except iam.exceptions.EntityAlreadyExistsException:
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        log(f"role {name} exists, trust and policy refreshed")
    iam.put_role_policy(
        RoleName=name, PolicyName="policy-warden", PolicyDocument=json.dumps(policy)
    )
    return arn


def ensure_guardrail():
    spec = json.loads((ROOT / "infra/guardrail.json").read_text())
    found = [
        g for g in bedrock.list_guardrails()["guardrails"] if g["name"] == spec["name"]
    ]
    if found:
        gid = found[0]["id"]
        bedrock.update_guardrail(guardrailIdentifier=gid, **spec)
        log(f"guardrail {gid} updated")
    else:
        gid = bedrock.create_guardrail(**spec)["guardrailId"]
        log(f"guardrail {gid} created")
    for _ in range(30):
        if bedrock.get_guardrail(guardrailIdentifier=gid)["status"] == "READY":
            break
        time.sleep(2)
    version = bedrock.create_guardrail_version(
        guardrailIdentifier=gid, description="policy-warden deploy"
    )["version"]
    log(f"guardrail version {version}")
    return gid, version


def gate_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / "hooks/gate.py", "gate.py")
        for name in ("__init__.py", "rules.py", "tools.py", "scanner.py", "config.py"):
            z.write(ROOT / "warden" / name, f"warden/{name}")
    return buf.getvalue()


def ensure_gate(role_arn, gid, gver):
    env = {"Variables": {"GUARDRAIL_ID": gid, "GUARDRAIL_VERSION": gver}}
    code = gate_zip()
    try:
        lam.get_function(FunctionName=GATE_FN)
        lam.update_function_code(FunctionName=GATE_FN, ZipFile=code)
        lam.get_waiter("function_updated_v2").wait(FunctionName=GATE_FN)
        lam.update_function_configuration(
            FunctionName=GATE_FN, Role=role_arn, Environment=env
        )
        log("gate Lambda updated")
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(12):  # a new role takes a few seconds to become assumable
            try:
                lam.create_function(
                    FunctionName=GATE_FN,
                    Runtime="python3.13",
                    Role=role_arn,
                    Handler="gate.lambda_handler",
                    Code={"ZipFile": code},
                    Timeout=30,
                    MemorySize=256,
                    Environment=env,
                    Tags={"app": config.PREFIX},
                )
                break
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 11:
                    raise
                time.sleep(5)
        log("gate Lambda created")
    lam.get_waiter("function_active_v2").wait(FunctionName=GATE_FN)
    return lam.get_function(FunctionName=GATE_FN)["Configuration"]["FunctionArn"]


def model_resources():
    prof = bedrock.get_inference_profile(inferenceProfileIdentifier=config.MODEL_ID)
    return [prof["inferenceProfileArn"]] + [m["modelArn"] for m in prof["models"]]


def harness_spec(role_arn, gate_arn):
    hook_target = {
        "lambda": {"arn": gate_arn, "timeoutSeconds": 30, "failureMode": "deny"}
    }
    return {
        "executionRoleArn": role_arn,
        "model": {
            "bedrockModelConfig": {
                "modelId": config.MODEL_ID,
                "maxTokens": config.MAX_TOKENS,
                "temperature": 0.0,
            }
        },
        "systemPrompt": [{"text": config.SYSTEM_PROMPT}],
        "tools": harness_tools(),
        "allowedTools": TOOL_NAMES,
        "hooks": [
            {"beforeInvocation": {"name": "screen_request", "target": hook_target}},
            {
                "beforeToolCall": {
                    "name": "allowlist_and_validate",
                    "target": hook_target,
                }
            },
            {"afterToolCall": {"name": "screen_tool_result", "target": hook_target}},
        ],
        "memory": {"disabled": {}},
        "maxIterations": config.MAX_ITERATIONS,
        "maxTokens": config.MAX_TOKENS,
        "timeoutSeconds": config.TIMEOUT_SECONDS,
    }


def ensure_harness(spec):
    found = [
        h
        for h in acc.list_harnesses().get("harnesses", [])
        if h.get("harnessName") == config.HARNESS_NAME
    ]
    if found:
        hid = found[0]["harnessId"]
        acc.update_harness(harnessId=hid, **spec)
        log(f"harness {hid} updated")
    else:
        for attempt in range(12):  # wait for the new execution role to propagate
            try:
                hid = acc.create_harness(
                    harnessName=config.HARNESS_NAME, tags={"app": config.PREFIX}, **spec
                )["harness"]["harnessId"]
                break
            except ClientError as e:
                if attempt == 11 or e.response["Error"]["Code"] not in (
                    "ValidationException",
                    "AccessDeniedException",
                ):
                    raise
                log(f"create_harness: {e.response['Error']['Message']} (retrying)")
                time.sleep(5)
        log(f"harness {hid} created")
    for _ in range(90):
        h = acc.get_harness(harnessId=hid)["harness"]
        if h["status"] == "READY":
            return h
        if h["status"].endswith("FAILED"):
            raise SystemExit(f"harness {h['status']}: {h.get('failureReason')}")
        time.sleep(5)
    raise SystemExit("harness did not reach READY in 7.5 minutes")


def main():
    log(f"account {ACCOUNT}, region {R}, model {config.MODEL_ID}")
    gid, gver = ensure_guardrail()

    gate_role = ensure_role(
        GATE_ROLE,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        fill("infra/iam/gate-policy.json", GUARDRAIL_ID=gid),
    )
    gate_arn = ensure_gate(gate_role, gid, gver)

    auditor_arn = ensure_role(
        AUDITOR_ROLE,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        json.loads((ROOT / "infra/iam/auditor-policy.json").read_text()),
    )

    harness_policy = fill(
        "infra/iam/harness-policy.json",
        MODEL_ID=config.MODEL_ID,
        GATE_ARN=gate_arn,
        HARNESS_NAME=config.HARNESS_NAME,
    )
    harness_policy["Statement"][0]["Resource"] = model_resources()
    harness_role = ensure_role(
        HARNESS_ROLE,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": ACCOUNT},
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:bedrock-agentcore:{R}:{ACCOUNT}:harness/*"
                        },
                    },
                }
            ],
        },
        harness_policy,
    )

    h = ensure_harness(harness_spec(harness_role, gate_arn))
    config.save_state(
        {
            "account": ACCOUNT,
            "region": R,
            "model": config.MODEL_ID,
            "guardrail_id": gid,
            "guardrail_version": gver,
            "gate_arn": gate_arn,
            "auditor_role_arn": auditor_arn,
            "harness_role_arn": harness_role,
            "harness_id": h["harnessId"],
            "harness_arn": h["arn"],
        }
    )
    log(f"READY {h['arn']}")


if __name__ == "__main__":
    main()
