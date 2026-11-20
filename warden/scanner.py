"""Read-only inventory of one AWS account, flattened into records the rule engine reads.

Every call here is a Describe/List/Get. It runs under the auditor role
(infra/iam/auditor-policy.json), which denies every non-read action, so a
bug or an injected instruction here cannot change the account.

Record shape:
    {"arn": str, "type": str, "region": str, "attrs": {...}, "tags": {...}}

Tag values are attacker-controllable (anyone who can tag a resource writes
them). They stay inside records and reach the model only as evidence for a
rule that names that tag key, after the gate Lambda's guardrail check.
"""

import datetime as dt
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

NOW = dt.datetime.now(dt.timezone.utc)


def _tags(tag_list):
    return {t["Key"]: t.get("Value", "") for t in tag_list or []}


def _age_days(ts):
    return (NOW - ts).days if ts else None


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(
        Filters=[
            {"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}
        ]
    )
    return sorted(r["RegionName"] for r in resp["Regions"])


def scan_region(session, account, region):
    ec2 = session.client("ec2", region_name=region)
    out = []

    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for i in res["Instances"]:
                out.append(
                    {
                        "arn": f"arn:aws:ec2:{region}:{account}:instance/{i['InstanceId']}",
                        "type": "ec2:instance",
                        "region": region,
                        "attrs": {
                            "instance_type": i["InstanceType"],
                            "state": i["State"]["Name"],
                            "age_days": _age_days(i.get("LaunchTime")),
                            "has_public_ip": bool(i.get("PublicIpAddress")),
                            "imdsv2_required": i.get("MetadataOptions", {}).get(
                                "HttpTokens"
                            )
                            == "required",
                        },
                        "tags": _tags(i.get("Tags")),
                    }
                )

    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            out.append(
                {
                    "arn": f"arn:aws:ec2:{region}:{account}:volume/{v['VolumeId']}",
                    "type": "ec2:volume",
                    "region": region,
                    "attrs": {
                        "size_gib": v["Size"],
                        "volume_type": v["VolumeType"],
                        "attached": bool(v.get("Attachments")),
                        "encrypted": v["Encrypted"],
                        "age_days": _age_days(v.get("CreateTime")),
                    },
                    "tags": _tags(v.get("Tags")),
                }
            )

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
                cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
                for cidr in cidrs:
                    out.append(
                        {
                            "arn": (
                                f"arn:aws:ec2:{region}:{account}:security-group/{sg['GroupId']}"
                                f"#{perm.get('IpProtocol')}:{perm.get('FromPort')}-{perm.get('ToPort')}:{cidr}"
                            ),
                            "type": "ec2:security-group-rule",
                            "region": region,
                            "attrs": {
                                "group_id": sg["GroupId"],
                                "group_name": sg["GroupName"],
                                "protocol": perm.get("IpProtocol"),
                                "from_port": perm.get("FromPort", -1),
                                "to_port": perm.get("ToPort", -1),
                                "cidr": cidr,
                                "open_to_world": cidr in ("0.0.0.0/0", "::/0"),
                            },
                            "tags": _tags(sg.get("Tags")),
                        }
                    )

    for a in ec2.describe_addresses().get("Addresses", []):
        out.append(
            {
                "arn": f"arn:aws:ec2:{region}:{account}:elastic-ip/{a.get('AllocationId', a['PublicIp'])}",
                "type": "ec2:elastic-ip",
                "region": region,
                "attrs": {
                    "associated": bool(a.get("AssociationId")),
                    "public_ip": a["PublicIp"],
                },
                "tags": _tags(a.get("Tags")),
            }
        )
    return out


def scan_buckets(session):
    s3 = session.client("s3")
    out = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        attrs = {"age_days": _age_days(b.get("CreationDate"))}
        try:
            loc = (
                s3.get_bucket_location(Bucket=name)["LocationConstraint"] or "us-east-1"
            )
        except ClientError:
            loc = "unknown"
        regional = session.client(
            "s3", region_name=loc if loc != "unknown" else "us-east-1"
        )
        try:
            cfg = regional.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
            attrs["public_access_blocked"] = all(cfg.values())
        except ClientError:
            attrs["public_access_blocked"] = False
        try:
            attrs["policy_is_public"] = regional.get_bucket_policy_status(Bucket=name)[
                "PolicyStatus"
            ]["IsPublic"]
        except ClientError:
            attrs["policy_is_public"] = False
        try:
            tags = _tags(regional.get_bucket_tagging(Bucket=name)["TagSet"])
        except ClientError:
            tags = {}
        out.append(
            {
                "arn": f"arn:aws:s3:::{name}",
                "type": "s3:bucket",
                "region": loc,
                "attrs": attrs,
                "tags": tags,
            }
        )
    return out


def scan_costs(session, account):
    ce = session.client("ce", region_name="us-east-1")
    start = NOW.date().replace(day=1)
    end = NOW.date() + dt.timedelta(days=1)
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    totals = {}
    for period in resp["ResultsByTime"]:
        for g in period["Groups"]:
            svc = g["Keys"][0]
            totals[svc] = totals.get(svc, 0.0) + float(
                g["Metrics"]["UnblendedCost"]["Amount"]
            )
    return [
        {
            "arn": f"cost:{account}:{svc}",
            "type": "cost:service",
            "region": "global",
            "attrs": {
                "service": svc,
                "month_to_date_usd": round(usd, 2),
                "period_start": start.isoformat(),
            },
            "tags": {},
        }
        for svc, usd in sorted(totals.items())
    ]


def scan_account(session, regions=None):
    """Return (records, errors). Errors are per-region strings, never raised."""
    account = session.client("sts").get_caller_identity()["Account"]
    regions = regions or enabled_regions(session)
    records, errors = [], []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(scan_region, session, account, r): r for r in regions}
        for fut, region in futures.items():
            try:
                records.extend(fut.result())
            except ClientError as e:
                errors.append(f"{region}: {e.response['Error']['Code']}")
    for fn in (lambda: scan_buckets(session), lambda: scan_costs(session, account)):
        try:
            records.extend(fn())
        except ClientError as e:
            errors.append(e.response["Error"]["Code"])
    return records, errors
