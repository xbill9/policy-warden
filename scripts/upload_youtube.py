#!/usr/bin/env python3
"""Upload media/policy-warden-demo.mp4 to YouTube as a public video.

    python3 scripts/upload_youtube.py [token.json]

Uses an authorized-user token with the youtube.upload scope (default
~/.config/youtube-upload/token.json). Prints the video URL.
"""

import json
import pathlib
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIDEO = ROOT / "media" / "policy-warden-demo.mp4"
TOKEN = pathlib.Path.home() / ".config" / "youtube-upload" / "token.json"


def links():
    out = {}
    for ln in (ROOT / "docs" / "links.txt").read_text().splitlines():
        if "=" in ln and not ln.startswith("#"):
            k, v = (s.strip() for s in ln.split("=", 1))
            out[k] = v
    return out


def main():
    token = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else TOKEN
    creds = Credentials.from_authorized_user_info(json.loads(token.read_text()))
    if not creds.valid:
        creds.refresh(Request())
        token.write_text(creds.to_json())
    run = json.loads((ROOT / "media" / "run.json").read_text())
    t = run["totals"]
    lk = links()
    description = (
        "Policy Warden checks an AWS account against a policy written in plain English and reports every "
        "violation with evidence. It runs on Amazon Bedrock AgentCore Harness with Amazon Nova 2 Lite. "
        "IAM, harness lifecycle hooks, a Bedrock Guardrail, the operator's approval and code enforce its rules; "
        "the model only compiles sentences into rules.\n\n"
        f"In this recording: a live check (run {run['run_id']}): {t['rules_proposed']} rules proposed, "
        f"{t['rules_approved']} approved, {t['violations']} violations across {run['scanned']} resources. "
        f"Then the stress test (run {run['stress']}): {run['passed']} of {run['cases']} hostile prompts stopped, "
        "including prompt injections hidden in resource tags.\n\n"
        f"Code (MIT): {lk['repo']}\n"
        f"Write-up on AWS Builder Center: {lk['builder']}\n"
        f"dev.to: {lk['devto-aws']}\n"
        f"Substack: {lk['substack']}\n\n"
        "Entry for the AWS Builder Center hackathon Agents, your rules: Bedrock Managed Agents build. "
        "No audio."
    )
    body = {
        "snippet": {
            "title": "Policy Warden: Plain-English AWS Policy Checks on Amazon Bedrock AgentCore Harness",
            "description": description,
            "tags": [
                "Amazon Bedrock",
                "AgentCore",
                "Amazon Nova",
                "AWS security",
                "AI agents",
                "prompt injection",
            ],
            "categoryId": "28",
        },
        "status": {"privacyStatus": "public", "selfDeclaredMadeForKids": False},
    }
    yt = build("youtube", "v3", credentials=creds)
    req = yt.videos().insert(
        part="snippet,status",
        body=body,
        media_body=MediaFileUpload(str(VIDEO), mimetype="video/mp4", resumable=True),
    )
    resp = None
    while resp is None:
        _, resp = req.next_chunk()
    print(
        f"https://youtu.be/{resp['id']}",
        resp["status"]["privacyStatus"],
        resp["status"].get("uploadStatus"),
    )


if __name__ == "__main__":
    main()
