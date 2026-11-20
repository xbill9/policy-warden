"""Scanner Lambda. Its execution role is the auditor role (infra/iam/auditor-policy.json):
reads only, with an explicit deny on every other action. The client invokes this
function for scan_account; no person or laptop ever holds the auditor role."""

import re

import boto3

from warden import scanner
from warden.tools import REGION_RE


def lambda_handler(event, _context):
    regions = event.get("regions") or None
    if regions is not None and (
        not isinstance(regions, list)
        or len(regions) > 40
        or not all(isinstance(r, str) and re.match(REGION_RE, r) for r in regions)
    ):
        return {"error": "regions must be a list of region names"}
    records, errors = scanner.scan_account(boto3.Session(), regions)
    return {"records": records, "errors": errors}
