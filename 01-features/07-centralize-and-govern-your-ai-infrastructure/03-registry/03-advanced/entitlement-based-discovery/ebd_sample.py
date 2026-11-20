"""Registry lifecycle and discovery helpers."""

import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import ClientError

JsonObject = dict[str, Any]
LOGGER = logging.getLogger(__name__)


def log_event(event: str, **fields: Any) -> None:
    """Emit one structured log entry without credentials or auth headers."""
    LOGGER.info(json.dumps({"event": event, **fields}, default=str))


def wait_for_status(
    read: Callable[[], JsonObject],
    expected: str,
    timeout: float,
    poll_seconds: float = 3,
) -> JsonObject:
    """Wait for an asynchronous registry or record transition with a deadline."""
    deadline = time.monotonic() + timeout
    previous = None
    while True:
        try:
            response = read()
            status = response["status"]
            if status == expected:
                return response
            if status.endswith("_FAILED") or status in {"REJECTED", "DEPRECATED"}:
                raise RuntimeError(f"Resource entered {status}: {response.get('statusReason', '')}")
        except ClientError as error:
            if error.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            status = "NOT_VISIBLE_YET"
        if status != previous:
            log_event("waiting_for_status", status=status, expected=expected)
            previous = status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for {expected}; last state: {status}")
        time.sleep(min(poll_seconds, remaining))


def save_state(path: Path, state: JsonObject) -> None:
    """Persist resource identifiers atomically so partial setup can be cleaned up."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n")
    temporary.replace(path)


def discover(client: BaseClient, state: JsonObject) -> JsonObject:
    """Read BatchGet, Search and every List page as the authenticated caller."""
    # Full ARNs also work for cross-account SigV4 discovery.
    registry_arn = state["registryArn"]
    record_ids = [record["recordId"] for record in state["records"]]
    if not record_ids:
        raise ValueError("The state file contains no records; setup was incomplete.")
    batch = client.batch_get_discoverable_registry_record(
        entries=[{"registryId": registry_arn, "recordIds": record_ids}]
    )
    search = client.search_discoverable_registry_records(registryIds=[registry_arn], searchQuery="", maxResults=20)
    listed = []
    next_token = None
    while True:
        request: JsonObject = {"registryId": registry_arn, "maxResults": 100}
        if next_token:
            request["nextToken"] = next_token
        page = client.list_discoverable_registry_records(**request)
        listed.extend(page["registryRecords"])
        next_token = page.get("nextToken")
        # A short or empty page can still have a cursor.
        if not next_token:
            break
    return {
        "batchGet": batch["registryRecords"],
        "batchErrors": batch["errors"],
        "search": search["registryRecords"],
        "list": listed,
    }


def cleanup(client: BaseClient, state: JsonObject) -> None:
    """Delete only the sample's recorded resources, then request registry deletion."""
    registry_arn = state["registryArn"]
    for record in state["records"]:
        try:
            client.delete_registry_record(registryId=registry_arn, recordId=record["recordId"])
        except ClientError as error:
            if error.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        response = client.delete_registry(registryId=registry_arn)
        log_event("registry_deletion_requested", registryArn=registry_arn, **response)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        log_event("registry_already_deleted", registryArn=registry_arn)
