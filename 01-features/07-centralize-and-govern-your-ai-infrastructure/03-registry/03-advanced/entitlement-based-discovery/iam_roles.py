"""Create discovery-only IAM roles for the platform walkthrough."""

import json
from pathlib import Path

from botocore.client import BaseClient
from botocore.exceptions import ClientError
from ebd_sample import JsonObject, save_state

POLICY_NAME = "RegistryDiscovery"


def create_roles(iam: BaseClient, state: JsonObject, state_file: Path, prefix: str, trusted_arn: str) -> None:
    """Create roles with the same discovery permissions and different tags."""
    if state["scenario"] != "iam" or not state["records"]:
        raise ValueError("Set up the IAM registry and publish its records first")
    registry = state["registryArn"]
    discover_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "agent-registry:ListDiscoverableRegistryRecords",
                    "agent-registry:SearchDiscoverableRegistryRecords",
                ],
                "Resource": registry,
            },
            {
                "Effect": "Allow",
                "Action": "agent-registry:GetDiscoverableRegistryRecord",
                "Resource": [f"{registry}/record/{record['recordId']}" for record in state["records"]],
            },
        ],
    }
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": trusted_arn},
            }
        ],
    }
    roles = state.setdefault("roles", {})
    for caller in ("prod", "dev", "untagged"):
        if caller not in roles:
            role = iam.create_role(
                RoleName=f"{prefix}-{caller}",
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[] if caller == "untagged" else [{"Key": "environment", "Value": caller}],
            )["Role"]
            roles[caller] = {"arn": role["Arn"], "name": role["RoleName"]}
            save_state(state_file, state)
        iam.put_role_policy(
            RoleName=roles[caller]["name"],
            PolicyName=POLICY_NAME,
            PolicyDocument=json.dumps(discover_policy),
        )
    print(json.dumps(roles, indent=2))


def delete_roles(iam: BaseClient, state: JsonObject) -> None:
    """Remove only the IAM roles recorded for this sample run."""
    for role in state.get("roles", {}).values():
        for operation in (
            lambda role=role: iam.delete_role_policy(RoleName=role["name"], PolicyName=POLICY_NAME),
            lambda role=role: iam.delete_role(RoleName=role["name"]),
        ):
            try:
                operation()
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchEntity":
                    raise
