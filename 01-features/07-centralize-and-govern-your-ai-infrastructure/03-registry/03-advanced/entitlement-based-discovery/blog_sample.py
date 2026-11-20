"""Run the IAM environments and JWT entitlements registry walkthroughs."""

import argparse
import json
import os
import time
import urllib.request
from pathlib import Path

import boto3
from blog_scenarios import (
    IAM_POLICY,
    IAM_RECORDS,
    IAM_SCHEMA,
    JWT_POLICY,
    JWT_RECORDS,
    JWT_SCHEMA,
)
from botocore import UNSIGNED
from botocore.client import BaseClient
from botocore.config import Config
from ebd_sample import (
    JsonObject,
    cleanup,
    discover,
    save_state,
    wait_for_status,
)
from iam_roles import create_roles, delete_roles

IAM_EXPECTED = {
    "prod": {"payments-mcp", "search-mcp"},
    "dev": {"payments-mcp", "search-mcp", "code-assistant-mcp"},
    "untagged": set(),
}
ENGINEERING = {"deployment-pipeline-mcp", "incident-management-mcp", "it-helpdesk-mcp"}
JWT_EXPECTED = {
    "finance": ENGINEERING | {"budget-forecasting-mcp"},
    "engineering": ENGINEERING,
    "hr-case": {"benefits-enrollment-mcp", "it-helpdesk-mcp"},
    "hr-audit": {
        "benefits-enrollment-mcp",
        "benefits-payroll-sync-mcp",
        "it-helpdesk-mcp",
    },
}


def approve(client: BaseClient, curator: BaseClient, request: JsonObject, timeout: float) -> None:
    """Submit the draft as publisher and approve it as curator."""
    read = lambda: client.get_registry_record(**request)
    wait_for_status(read, "DRAFT", timeout)
    client.submit_registry_record_for_approval(**request)
    wait_for_status(read, "PENDING_APPROVAL", timeout)
    curator.update_registry_record_status(**request, status="APPROVED", statusReason="Reviewed sample metadata")
    wait_for_status(read, "APPROVED", timeout)


def setup(args: argparse.Namespace, client: BaseClient, curator: BaseClient) -> None:
    """Create the selected registry, attach its policy, and publish the fixtures."""
    if args.state.exists():
        raise ValueError(f"State already exists: {args.state}")
    if args.scenario == "jwt":
        if not args.discovery_url or not args.allowed_client:
            raise ValueError("JWT setup requires --discovery-url and one or more --allowed-client values")
        auth = {
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {
                    "discoveryUrl": args.discovery_url,
                    "allowedClients": args.allowed_client,
                }
            },
        }
        schema, policy, records = JWT_SCHEMA, JWT_POLICY, JWT_RECORDS
    else:
        auth = {"authorizerType": "AWS_IAM"}
        schema, policy, records = IAM_SCHEMA, IAM_POLICY, IAM_RECORDS
    arn = client.create_registry(
        name=args.name,
        discoveryConfiguration=auth,
        approvalConfiguration={"autoApprovalRules": []},
        customMetadataSchemaConfiguration={"defaultSchema": json.dumps(schema)},
    )["registryArn"]
    state = {
        "registryArn": arn,
        "scenario": args.scenario,
        "records": [],
        "promoted": False,
    }
    save_state(args.state, state)
    read = lambda: client.get_registry(registryId=arn)
    wait_for_status(read, "READY", args.timeout)
    client.update_registry(
        registryId=arn,
        discoveryPolicy={"put": {"document": json.dumps(policy), "revision": "NO_POLICY"}},
    )
    wait_for_status(read, "READY", args.timeout)
    for name, metadata in records.items():
        result = client.create_registry_record(
            registryId=arn,
            name=name,
            recordType="MCP",
            recordVersion="1.0.0",
            customMetadata=metadata,
            descriptors={
                "mcpServer": {
                    "dataSchemaVersion": "2025-12-11",
                    "data": json.dumps(
                        {
                            "name": f"io.example/{name}",
                            "version": "1.0.0",
                            "description": name.replace("-", " "),
                        }
                    ),
                }
            },
        )
        record_id = result["recordArn"].rsplit("/", 1)[-1]
        state["records"].append({"name": name, "recordId": record_id})
        save_state(args.state, state)
        approve(client, curator, {"registryId": arn, "recordId": record_id}, args.timeout)


def jwt_discover(state: JsonObject, token: str, query: str, endpoint: str) -> JsonObject:
    """Call the JWT discovery APIs directly with an access token."""
    registry = state["registryArn"].rsplit("/", 1)[-1]

    def post(path: str, payload: JsonObject) -> JsonObject:
        request = urllib.request.Request(
            endpoint.rstrip("/") + path,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    listed = []
    request = {"maxResults": 50}
    while True:
        page = post(f"/registries/{registry}/discoverable-records-list", request)
        listed.extend(page["registryRecords"])
        if not page.get("nextToken"):
            break
        request["nextToken"] = page["nextToken"]
    batch = post(
        "/discoverable-records-batch",
        {
            "entries": [
                {
                    "registryId": registry,
                    "recordIds": [record["recordId"] for record in state["records"]],
                }
            ]
        },
    )
    search = post(
        "/discoverable-records-search",
        {"registryIds": [registry], "searchQuery": query, "maxResults": 10},
    )
    return {
        "list": listed,
        "batchGet": batch["registryRecords"],
        "batchErrors": batch["errors"],
        "search": search["registryRecords"],
    }


def matches(results: JsonObject, state: JsonObject, expected: set[str]) -> bool:
    """Require exact List and BatchGet catalogs and a filtered Search subset."""
    hidden = {record["recordId"] for record in state["records"] if record["name"] not in expected}
    errors = results["batchErrors"]
    if any(error["errorCode"] != "RESOURCE_NOT_FOUND" for error in errors):
        raise RuntimeError(f"Unexpected BatchGet errors: {errors}")
    return (
        all({record["name"] for record in results[key]} == expected for key in ("list", "batchGet"))
        and {record["recordId"] for record in errors} == hidden
        and {record["name"] for record in results["search"]} <= expected
    )


def promote(
    owner: BaseClient,
    curator: BaseClient,
    state: JsonObject,
    state_file: Path,
    timeout: float,
) -> None:
    """Update and approve a new version of the preview record."""
    record_id = next(record["recordId"] for record in state["records"] if record["name"] == "code-assistant-mcp")
    request = {"registryId": state["registryArn"], "recordId": record_id}
    owner.update_registry_record(
        **request,
        recordVersion="1.1.0",
        customMetadata={"optionalValue": {"stage": "production", "under_review": False}},
    )
    approve(owner, curator, request, timeout)
    state["promoted"] = True
    save_state(state_file, state)


def main() -> None:
    """Parse commands and run one scenario against the regional AWS endpoints."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=600)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("setup", "promote", "cleanup"):
        sub = commands.add_parser(command)
        sub.add_argument("--owner-profile", required=True)
        if command != "cleanup":
            sub.add_argument("--curator-profile")
        if command == "setup":
            sub.add_argument("--scenario", choices=("iam", "jwt"), required=True)
            sub.add_argument("--name", required=True)
            sub.add_argument("--discovery-url")
            sub.add_argument("--allowed-client", action="append")
    roles = commands.add_parser("create-roles")
    roles.add_argument("--owner-profile", required=True)
    roles.add_argument("--prefix", required=True)
    roles.add_argument("--trusted-arn", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--caller", required=True, choices=tuple(IAM_EXPECTED) + tuple(JWT_EXPECTED))
    check.add_argument("--profile")
    check.add_argument("--token-env", default="EBD_ACCESS_TOKEN")
    check.add_argument("--query", default="pay employees and manage their benefits")
    args = parser.parse_args()

    def sdk(service: str, profile: str | None = None) -> BaseClient:
        return boto3.Session(profile_name=profile).client(
            service,
            region_name=args.region,
            config=Config(retries={"mode": "adaptive"}),
        )

    if args.command == "setup":
        owner = sdk("agent-registry-control", args.owner_profile)
        curator = sdk("agent-registry-control", args.curator_profile) if args.curator_profile else owner
        setup(args, owner, curator)
        return
    state = json.loads(args.state.read_text())
    if args.command == "create-roles":
        iam = boto3.Session(profile_name=args.owner_profile).client("iam", region_name=args.region)
        create_roles(iam, state, args.state, args.prefix, args.trusted_arn)
        return
    if args.command == "verify":
        if state["scenario"] == "iam":
            if not args.profile or args.caller not in IAM_EXPECTED:
                parser.error("IAM verification requires an IAM caller and --profile")
            client = sdk("agent-registry", args.profile)
            expected = IAM_EXPECTED[args.caller].copy()
            if args.caller == "prod" and state["promoted"]:
                expected.add("code-assistant-mcp")
            read = lambda: discover(client, state)
        else:
            if args.caller not in JWT_EXPECTED or not os.environ.get(args.token_env):
                parser.error("JWT verification requires a JWT caller and an access token in --token-env")
            expected = JWT_EXPECTED[args.caller]
            endpoint = boto3.client(
                "agent-registry",
                region_name=args.region,
                config=Config(signature_version=UNSIGNED),
            ).meta.endpoint_url
            read = lambda: jwt_discover(state, os.environ[args.token_env], args.query, endpoint)
        deadline = time.monotonic() + args.timeout
        while True:
            results = read()
            if matches(results, state, expected):
                print(
                    json.dumps(
                        {
                            key: sorted(record["name"] for record in results[key])
                            for key in ("list", "batchGet", "search")
                        },
                        indent=2,
                    )
                )
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Expected catalog {sorted(expected)}; received {results}")
            time.sleep(3)
    owner = sdk("agent-registry-control", args.owner_profile)
    if args.command == "cleanup":
        cleanup(owner, state)
        if state.get("roles"):
            iam = boto3.Session(profile_name=args.owner_profile).client("iam", region_name=args.region)
            delete_roles(iam, state)
        return
    if state["scenario"] != "iam" or state["promoted"]:
        parser.error("Promotion requires an IAM registry with an unpromoted preview record")
    curator = sdk("agent-registry-control", args.curator_profile) if args.curator_profile else owner
    promote(owner, curator, state, args.state, args.timeout)


if __name__ == "__main__":
    main()
