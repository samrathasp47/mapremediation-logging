#!/usr/bin/env python3
"""
OCI CIS logging remediation script.

Checks:
  1. Object Storage buckets: enables read and write service logs.
  2. Subnets: enables VCN flow logs.

Requirements:
  pip install oci

Examples:
  # Create required resources automatically and report planned changes.
  python oci_logging_remediation.py --compartment-id ocid1.compartment.oc1..aaaa... --dry-run

  # Reuse separate existing resources.
  python oci_logging_remediation.py \
    --bucket-log-group-id ocid1.loggroup.oc1..aaaa... \
    --flow-log-group-id ocid1.loggroup.oc1..bbbb... \
    --subnet-capture-filter-id ocid1.capturefilter.oc1..cccc...
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import oci
from oci.exceptions import ServiceError


OBJECT_STORAGE_SERVICE = "objectstorage"
OBJECT_STORAGE_CATEGORIES = ("read", "write")

# OCI VCN Flow Logs are service logs. In most tenancies the service is "flowlogs"
# and the category is "subnet". If your tenancy exposes different values, run with
# --show-log-categories and update these constants.
FLOW_LOG_SERVICE = "flowlogs"
FLOW_LOG_CATEGORIES = ("subnet",)


@dataclass(frozen=True)
class DesiredLog:
    display_name: str
    compartment_id: str
    log_group_id: str
    service: str
    resource: str
    category: str
    source_parameters: Optional[Dict[str, str]] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enable OCI Object Storage bucket read/write logs and subnet flow logs where missing."
    )
    parser.add_argument(
        "--tenancy-id",
        help="Tenancy OCID to scan. Defaults to the tenancy OCID from the OCI config profile.",
    )
    parser.add_argument(
        "--compartment-id",
        help="Optional compartment OCID to scan instead of the whole tenancy. Child compartments are included by default.",
    )
    parser.add_argument("--config-file", default=oci.config.DEFAULT_LOCATION, help="OCI config file path.")
    parser.add_argument("--profile", default=oci.config.DEFAULT_PROFILE, help="OCI config profile.")
    region_scope = parser.add_mutually_exclusive_group()
    region_scope.add_argument("--region", help="Override region from OCI config.")
    region_scope.add_argument(
        "--all-regions",
        action="store_true",
        help="Run independently in every READY region subscribed to the tenancy.",
    )
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument("--log-group-id", help="Existing shared log group OCID for both remediations (legacy option).")
    log_group.add_argument("--log-group-name", help="Existing shared log group name for both remediations (legacy option).")
    parser.add_argument(
        "--log-group-compartment-id",
        help="Compartment OCID containing --log-group-name. Recommended when using --log-group-name.",
    )
    parser.add_argument("--resource-compartment-id", help="Compartment for auto-created log groups and capture filter. Defaults to the scan root.")
    bucket_log_group = parser.add_mutually_exclusive_group()
    bucket_log_group.add_argument("--bucket-log-group-id", help="Existing log group OCID for Object Storage logs.")
    bucket_log_group.add_argument("--bucket-log-group-name", help="Existing log group name for Object Storage logs.")
    parser.add_argument("--bucket-log-group-compartment-id", help="Compartment containing --bucket-log-group-name.")
    flow_log_group = parser.add_mutually_exclusive_group()
    flow_log_group.add_argument("--flow-log-group-id", help="Existing log group OCID for subnet flow logs.")
    flow_log_group.add_argument("--flow-log-group-name", help="Existing log group name for subnet flow logs.")
    parser.add_argument("--flow-log-group-compartment-id", help="Compartment containing --flow-log-group-name.")
    parser.add_argument(
        "--current-compartment-only",
        action="store_true",
        help="Only scan the selected compartment, not its child compartments.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only report actions. Do not create or enable logs.")
    parser.add_argument("--skip-buckets", action="store_true", help="Do not check or remediate bucket logs.")
    parser.add_argument("--skip-subnets", action="store_true", help="Do not check or remediate subnet flow logs.")
    parser.add_argument(
        "--bucket-findings-csv",
        help="CIS 4.17 findings CSV. Only bucket IDs in its required 'id' column are remediated.",
    )
    parser.add_argument(
        "--subnet-findings-csv",
        help="CIS 4.13 findings CSV. Only subnet IDs in its required 'id' column are remediated.",
    )
    parser.add_argument(
        "--bucket-service",
        default=OBJECT_STORAGE_SERVICE,
        help="OCI Logging service name for Object Storage bucket logs.",
    )
    parser.add_argument(
        "--bucket-categories",
        default=",".join(OBJECT_STORAGE_CATEGORIES),
        help="Comma-separated OCI Logging categories for Object Storage bucket logs.",
    )
    parser.add_argument(
        "--subnet-flow-service",
        default=FLOW_LOG_SERVICE,
        help="OCI Logging service name for subnet flow logs.",
    )
    parser.add_argument(
        "--subnet-flow-categories",
        default=",".join(FLOW_LOG_CATEGORIES),
        help="Comma-separated OCI Logging categories for subnet flow logs.",
    )
    parser.add_argument(
        "--subnet-capture-filter-id",
        help="Existing FLOWLOG capture filter OCID to attach to every newly created subnet flow log.",
    )
    parser.add_argument("--capture-filter-name", default="cis-vcn-flow-log-capture-filter", help="Name for an auto-created FLOWLOG capture filter.")
    parser.add_argument(
        "--flow-log-sampling-interval",
        type=int,
        default=1,
        help="Sampling interval for an auto-created capture filter: 1 means capture every flow (default: 1).",
    )
    parser.add_argument(
        "--show-log-categories",
        action="store_true",
        help="Print available Logging service/category values for each compartment before remediation.",
    )
    return parser.parse_args()


def split_csv(value: str) -> Tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def load_finding_ids(
    csv_path: str,
    finding_name: str,
    expected_ocid_prefix: str,
    region: Optional[str] = None,
) -> Set[str]:
    """Read non-empty OCI resource IDs from a CIS finding export."""
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames or "id" not in reader.fieldnames:
                raise RuntimeError(f"{finding_name} CSV must contain an 'id' column: {csv_path}")
            resource_ids = {
                row.get("id", "").strip()
                for row in reader
                if row.get("id", "").strip()
                and (not region or not row.get("region", "").strip() or row.get("region", "").strip() == region)
            }
            invalid_ids = [resource_id for resource_id in resource_ids if not resource_id.startswith(expected_ocid_prefix)]
            if invalid_ids:
                raise RuntimeError(
                    f"{finding_name} CSV contains {len(invalid_ids)} non-{expected_ocid_prefix} resource ID(s). "
                    "Use the CIS finding export with OCI resource OCIDs in the 'id' column."
                )
            return resource_ids
    except OSError as exc:
        raise RuntimeError(f"Could not read {finding_name} CSV '{csv_path}': {exc}") from exc


def load_finding_compartment_ids(csv_path: str, finding_name: str, region: Optional[str] = None) -> Set[str]:
    """Read target resource-compartment OCIDs from a CIS finding export."""
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames or "compartment_id" not in reader.fieldnames:
                raise RuntimeError(f"{finding_name} CSV must contain a 'compartment_id' column: {csv_path}")
            return {
                row.get("compartment_id", "").strip()
                for row in reader
                if row.get("compartment_id", "").strip()
                and (not region or not row.get("region", "").strip() or row.get("region", "").strip() == region)
            }
    except OSError as exc:
        raise RuntimeError(f"Could not read {finding_name} CSV '{csv_path}': {exc}") from exc


def load_finding_regions(csv_path: str, finding_name: str) -> Set[str]:
    """Read regions represented by a CIS finding export, ignoring blank rows."""
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames or "region" not in reader.fieldnames:
                return set()
            return {row.get("region", "").strip() for row in reader if row.get("region", "").strip()}
    except OSError as exc:
        raise RuntimeError(f"Could not read {finding_name} CSV '{csv_path}': {exc}") from exc


def load_config(args: argparse.Namespace) -> Dict:
    config = oci.config.from_file(args.config_file, args.profile)
    if args.region:
        config["region"] = args.region
    oci.config.validate_config(config)
    return config


def active_compartments(identity_client, root_compartment_id: str, current_compartment_only: bool) -> List[str]:
    if current_compartment_only:
        return [root_compartment_id]

    # OCI only supports compartment_id_in_subtree when the starting ID is the
    # tenancy (root) OCID. Walk one level at a time so --compartment-id accepts
    # either a tenancy OCID or any accessible parent compartment OCID.
    compartments = []
    pending = [root_compartment_id]
    while pending:
        compartment_id = pending.pop()
        compartments.append(compartment_id)
        children = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            compartment_id,
            access_level="ACCESSIBLE",
            lifecycle_state="ACTIVE",
        ).data
        pending.extend(compartment.id for compartment in children)
    return compartments


def resolve_or_create_log_group(
    logging_client,
    log_group_id: Optional[str],
    log_group_name: Optional[str],
    log_group_compartment_id: str,
    default_name: str,
    dry_run: bool,
) -> str:
    if log_group_id:
        print(f"Using supplied log group OCID: {log_group_id}")
        return log_group_id

    name = log_group_name or default_name
    search_compartments = [log_group_compartment_id]
    matches = []
    for compartment_id in search_compartments:
        groups = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups,
            compartment_id=compartment_id,
            display_name=name,
        ).data
        matches.extend(group for group in groups if group.lifecycle_state != "DELETED")

    if not matches:
        if dry_run:
            print(f"[DRY-RUN] Would create log group '{name}' in {log_group_compartment_id}")
            return f"dry-run-{name}"
        details = oci.logging.models.CreateLogGroupDetails(
            compartment_id=log_group_compartment_id,
            display_name=name,
        )
        response = logging_client.create_log_group(details)
        work_request_id = response.headers.get("opc-work-request-id")
        if work_request_id:
            work_request = oci.wait_until(
                logging_client,
                logging_client.get_work_request(work_request_id),
                evaluate_response=lambda result: result.data.status in ("SUCCEEDED", "FAILED", "CANCELED"),
                max_wait_seconds=300,
                max_interval_seconds=10,
            ).data
            if work_request.status != "SUCCEEDED":
                raise RuntimeError(
                    f"Log group creation for '{name}' did not succeed; work request {work_request_id} is {work_request.status}."
                )

        # CreateLogGroup returns no resource payload. Resolve the completed
        # resource by its unique display name before it is used as a destination.
        matches = [
            group
            for group in oci.pagination.list_call_get_all_results(
                logging_client.list_log_groups,
                compartment_id=log_group_compartment_id,
                display_name=name,
            ).data
            if group.lifecycle_state != "DELETED"
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Created log group '{name}' could not be uniquely resolved in {log_group_compartment_id}.")
        group = matches[0]
        print(f"[CREATE] Log group '{name}' -> {group.id}")
        return group.id

    if len(matches) > 1:
        print(f"Found multiple existing log groups named '{name}':", file=sys.stderr)
        for group in matches:
            print(f"  {group.id} in compartment {group.compartment_id}", file=sys.stderr)
        raise RuntimeError("Use the matching --*-log-group-id or --*-log-group-compartment-id to select one log group.")

    group = matches[0]
    print(f"Using existing log group '{group.display_name}' -> {group.id}")
    return group.id


def resolve_or_create_capture_filter(
    virtual_network_client,
    capture_filter_id: Optional[str],
    compartment_id: str,
    display_name: str,
    sampling_interval: int,
    dry_run: bool,
) -> str:
    if capture_filter_id:
        print(f"Using existing FLOWLOG capture filter: {capture_filter_id}")
        return capture_filter_id
    if sampling_interval < 1 or sampling_interval > 100000:
        raise RuntimeError("--flow-log-sampling-interval must be between 1 and 100000.")

    matching_filters = oci.pagination.list_call_get_all_results(
        virtual_network_client.list_capture_filters,
        compartment_id=compartment_id,
        display_name=display_name,
    ).data
    matching_filters = [
        capture_filter
        for capture_filter in matching_filters
        if capture_filter.lifecycle_state != "TERMINATED" and capture_filter.filter_type == "FLOWLOG"
    ]
    if len(matching_filters) == 1:
        capture_filter = matching_filters[0]
        print(f"Using existing FLOWLOG capture filter '{display_name}' -> {capture_filter.id}")
        return capture_filter.id
    if len(matching_filters) > 1:
        raise RuntimeError(
            f"Found multiple FLOWLOG capture filters named '{display_name}' in {compartment_id}. "
            "Use --subnet-capture-filter-id to select one."
        )

    if dry_run:
        print(
            "[DRY-RUN] Would create FLOWLOG capture filter "
            f"'{display_name}' in {compartment_id} with an enabled ALL/INCLUDE rule and sampling interval {sampling_interval}."
        )
        return "dry-run-capture-filter"

    rule = oci.core.models.FlowLogCaptureFilterRuleDetails(
        is_enabled=True,
        priority=0,
        sampling_rate=sampling_interval,
        flow_log_type="ALL",
        rule_action="INCLUDE",
    )
    details = oci.core.models.CreateCaptureFilterDetails(
        compartment_id=compartment_id,
        display_name=display_name,
        filter_type="FLOWLOG",
        flow_log_capture_filter_rules=[rule],
    )
    capture_filter = virtual_network_client.create_capture_filter(details).data
    print(f"[CREATE] FLOWLOG capture filter '{display_name}' -> {capture_filter.id}")
    return capture_filter.id


def list_all_logs(logging_client, compartment_id: str) -> List:
    logs = []
    groups = oci.pagination.list_call_get_all_results(
        logging_client.list_log_groups,
        compartment_id=compartment_id,
    ).data

    for group in groups:
        if group.lifecycle_state == "DELETED":
            continue
        group_logs = oci.pagination.list_call_get_all_results(
            logging_client.list_logs,
            log_group_id=group.id,
        ).data
        logs.extend(group_logs)
    return logs


def source_key(log) -> Optional[Tuple[str, str, str]]:
    config = getattr(log, "configuration", None)
    source = getattr(config, "source", None)
    if not source:
        return None
    return (
        get_model_value(source, "service"),
        get_model_value(source, "resource"),
        get_model_value(source, "category"),
    )


def get_model_value(model, name: str):
    if hasattr(model, name):
        return getattr(model, name)
    if isinstance(model, dict):
        return model.get(name)
    return None


def set_model_value(model, name: str, value) -> None:
    if isinstance(model, dict):
        model[name] = value
    else:
        setattr(model, name, value)
        register_model_field(model, name)


def register_model_field(model, name: str) -> None:
    swagger_types = getattr(model, "swagger_types", None)
    attribute_map = getattr(model, "attribute_map", None)

    if isinstance(swagger_types, dict) and name not in swagger_types:
        swagger_types[name] = "object"

    if isinstance(attribute_map, dict) and name not in attribute_map:
        attribute_map[name] = to_camel_case(name)


def to_camel_case(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


def enabled_log_keys(logging_client, compartment_id: str) -> Set[Tuple[str, str, str]]:
    keys = set()
    for log in list_all_logs(logging_client, compartment_id):
        key = source_key(log)
        if key and log.lifecycle_state != "DELETED" and log.is_enabled:
            keys.add(key)
    return keys


def disabled_matching_logs(logging_client, compartment_id: str) -> Dict[Tuple[str, str, str], str]:
    matches = {}
    for log in list_all_logs(logging_client, compartment_id):
        key = source_key(log)
        if key and log.lifecycle_state != "DELETED" and not log.is_enabled:
            matches[key] = log.id
    return matches


def list_buckets(object_storage_client, namespace: str, compartment_id: str) -> Iterable:
    return oci.pagination.list_call_get_all_results(
        object_storage_client.list_buckets,
        namespace,
        compartment_id,
    ).data


def list_subnets(virtual_network_client, compartment_id: str) -> Iterable:
    return oci.pagination.list_call_get_all_results(
        virtual_network_client.list_subnets,
        compartment_id,
        lifecycle_state="AVAILABLE",
    ).data


def bucket_ocid(object_storage_client, namespace: str, bucket) -> Optional[str]:
    """Return a bucket OCID, fetching full details when ListBuckets omits it."""
    bucket_id = get_model_value(bucket, "id")
    if bucket_id:
        return bucket_id
    try:
        return object_storage_client.get_bucket(namespace, bucket.name).data.id
    except ServiceError as exc:
        print(f"[WARN] Could not resolve OCID for bucket '{bucket.name}': {exc.message}")
        return None


def desired_bucket_logs(
    object_storage_client,
    namespace: str,
    compartment_id: str,
    log_group_id: str,
    service: str,
    categories: Tuple[str, ...],
    target_bucket_ids: Optional[Set[str]] = None,
    matched_bucket_ids: Optional[Set[str]] = None,
) -> List[DesiredLog]:
    desired = []
    for bucket in list_buckets(object_storage_client, namespace, compartment_id):
        bucket_id = bucket_ocid(object_storage_client, namespace, bucket) if target_bucket_ids is not None else None
        if target_bucket_ids is not None and bucket_id not in target_bucket_ids:
            continue
        if matched_bucket_ids is not None and bucket_id:
            matched_bucket_ids.add(bucket_id)
        for category in categories:
            desired.append(
                DesiredLog(
                    display_name=f"bucket-{bucket.name}-{category}",
                    compartment_id=compartment_id,
                    log_group_id=log_group_id,
                    service=service,
                    resource=bucket.name,
                    category=category,
                )
            )
    return desired


def desired_subnet_logs(
    virtual_network_client,
    compartment_id: str,
    log_group_id: str,
    service: str,
    categories: Tuple[str, ...],
    capture_filter_id: str,
    target_subnet_ids: Optional[Set[str]] = None,
    matched_subnet_ids: Optional[Set[str]] = None,
) -> List[DesiredLog]:
    desired = []
    for subnet in list_subnets(virtual_network_client, compartment_id):
        if target_subnet_ids is not None and subnet.id not in target_subnet_ids:
            continue
        if matched_subnet_ids is not None:
            matched_subnet_ids.add(subnet.id)
        subnet_name = subnet.display_name or subnet.id.rsplit(".", 1)[-1]
        # Subnet display names can repeat across compartments, while log display
        # names must be unique within the destination Log Group.
        subnet_suffix = subnet.id.rsplit(".", 1)[-1][-8:]
        for category in categories:
            desired.append(
                DesiredLog(
                    display_name=f"subnet-{subnet_name}-{subnet_suffix}-flowlogs",
                    compartment_id=compartment_id,
                    log_group_id=log_group_id,
                    service=service,
                    resource=subnet.id,
                    category=category,
                    source_parameters={
                        "capture_filter": capture_filter_id,
                        "enablementPointType": "Subnet",
                    },
                )
            )
    return desired


def enable_existing_log(logging_client, log_id: str, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] Would enable disabled log {log_id}")
        return

    details = oci.logging.models.UpdateLogDetails(is_enabled=True)
    logging_client.update_log(log_id, details)
    print(f"[ENABLE] Existing disabled log {log_id}")


def build_service_log_source(desired: DesiredLog):
    source = oci.logging.models.Source()
    set_model_value(source, "source_type", "OCISERVICE")
    set_model_value(source, "service", desired.service)
    set_model_value(source, "resource", desired.resource)
    set_model_value(source, "category", desired.category)
    if desired.source_parameters:
        set_model_value(source, "parameters", desired.source_parameters)
    return source


def create_service_log(logging_client, desired: DesiredLog, dry_run: bool) -> None:
    if dry_run:
        print(
            "[DRY-RUN] Would create service log "
            f"name={desired.display_name}, service={desired.service}, "
            f"resource={desired.resource}, category={desired.category}"
        )
        return

    source = build_service_log_source(desired)

    configuration = oci.logging.models.Configuration()
    set_model_value(configuration, "source", source)
    details = oci.logging.models.CreateLogDetails()
    set_model_value(details, "display_name", desired.display_name)
    set_model_value(details, "log_type", "SERVICE")
    set_model_value(details, "is_enabled", True)
    set_model_value(details, "configuration", configuration)

    try:
        response = logging_client.create_log(desired.log_group_id, details)
    except ServiceError as exc:
        if exc.status == 400 and exc.code == "InvalidParameter":
            print(
                "[SKIP] OCI rejected service log creation "
                f"service={desired.service}, resource={desired.resource}, category={desired.category}: {exc.message}"
            )
            print(f"       Source payload: {json.dumps(model_to_dict(source), sort_keys=True)}")
            print("       Run again with --show-log-categories --dry-run, then pass the matching service/category override.")
            return
        raise
    log = response.data
    if log and log.id:
        print(
            "[CREATE] Service log "
            f"{log.id} for service={desired.service}, resource={desired.resource}, category={desired.category}"
        )
        return

    work_request_id = response.headers.get("opc-work-request-id")
    if work_request_id:
        print(f"[CREATE] Service log request accepted. Work request: {work_request_id}")
    else:
        print(
            "[CREATE] Service log request accepted "
            f"for service={desired.service}, resource={desired.resource}, category={desired.category}"
        )


def model_to_dict(model):
    if isinstance(model, dict):
        return model

    result = {}
    attribute_map = getattr(model, "attribute_map", {}) or {}
    for attr_name, json_name in attribute_map.items():
        if not hasattr(model, attr_name):
            continue
        value = getattr(model, attr_name)
        if value is None:
            continue
        result[json_name] = model_to_dict(value)
    return result


def build_log_indexes(logging_client, compartment_ids: List[str]) -> Dict[Tuple[str, str, str], object]:
    logs_by_source = {}

    for compartment_id in compartment_ids:
        try:
            for log in list_all_logs(logging_client, compartment_id):
                key = source_key(log)
                if not key or log.lifecycle_state == "DELETED":
                    continue
                logs_by_source[key] = log
        except ServiceError as exc:
            print(f"[WARN] Could not list logs in compartment {compartment_id}: {exc.message}")

    return logs_by_source


def matching_existing_log(existing_logs: Dict[Tuple[str, str, str], object], desired: DesiredLog):
    key = (desired.service, desired.resource, desired.category)
    existing_log = existing_logs.get(key)
    if existing_log:
        return existing_log

    # Earlier versions of this script used OCI's legacy "all" category for
    # subnet flow logs. Treat it as the same enablement point so it is not
    # duplicated by this additive-only remediation.
    if desired.source_parameters and desired.category == "subnet":
        return existing_logs.get((desired.service, desired.resource, "all"))
    return None


def remediate(
    logging_client,
    desired_logs: List[DesiredLog],
    existing_logs: Dict[Tuple[str, str, str], object],
    dry_run: bool,
) -> None:
    if not desired_logs:
        return

    for desired in desired_logs:
        existing_log = matching_existing_log(existing_logs, desired)
        if existing_log and existing_log.is_enabled:
            print(
                "[OK] Logging already enabled "
                f"service={desired.service}, resource={desired.resource}, category={desired.category}"
            )
        elif existing_log:
            enable_existing_log(logging_client, existing_log.id, dry_run)
        else:
            create_service_log(logging_client, desired, dry_run)


def show_log_categories(logging_client, compartment_id: str) -> None:
    print(f"\nAvailable service log categories in compartment {compartment_id}:")
    try:
        services = oci.pagination.list_call_get_all_results(
            logging_client.list_services,
            compartment_id=compartment_id,
        ).data
        for service in services:
            print(f"  service={service.name}")
            categories = oci.pagination.list_call_get_all_results(
                logging_client.list_log_categories,
                compartment_id=compartment_id,
                service=service.name,
            ).data
            for category in categories:
                print(f"    category={category.name}")
    except ServiceError as exc:
        print(f"  Could not list categories: {exc.message}")


def run_region(args: argparse.Namespace, config: Dict) -> int:
    bucket_target_ids = (
        load_finding_ids(args.bucket_findings_csv, "CIS 4.17", "ocid1.bucket.", config["region"])
        if args.bucket_findings_csv
        else None
    )
    subnet_target_ids = (
        load_finding_ids(args.subnet_findings_csv, "CIS 4.13", "ocid1.subnet.", config["region"])
        if args.subnet_findings_csv
        else None
    )
    bucket_target_compartment_ids = (
        load_finding_compartment_ids(args.bucket_findings_csv, "CIS 4.17", config["region"])
        if args.bucket_findings_csv
        else None
    )
    subnet_target_compartment_ids = (
        load_finding_compartment_ids(args.subnet_findings_csv, "CIS 4.13", config["region"])
        if args.subnet_findings_csv
        else None
    )
    if bucket_target_ids is not None:
        print(f"Loaded {len(bucket_target_ids)} bucket finding ID(s) from {args.bucket_findings_csv}.")
    if subnet_target_ids is not None:
        print(f"Loaded {len(subnet_target_ids)} subnet finding ID(s) from {args.subnet_findings_csv}.")

    identity_client = oci.identity.IdentityClient(config)
    logging_client = oci.logging.LoggingManagementClient(config)
    object_storage_client = oci.object_storage.ObjectStorageClient(config)
    virtual_network_client = oci.core.VirtualNetworkClient(config)

    tenancy_id = args.tenancy_id or config["tenancy"]
    scan_root_compartment_id = args.compartment_id or tenancy_id
    namespace = object_storage_client.get_namespace().data
    requires_full_compartment_scan = (
        (not args.skip_buckets and bucket_target_ids is None)
        or (not args.skip_subnets and subnet_target_ids is None)
    )
    if requires_full_compartment_scan:
        compartment_ids = active_compartments(
            identity_client,
            scan_root_compartment_id,
            args.current_compartment_only,
        )
    else:
        compartment_ids = sorted((bucket_target_compartment_ids or set()) | (subnet_target_compartment_ids or set()))
        print(f"CSV-targeted mode: scanning {len(compartment_ids)} listed resource compartment(s).")
    resource_compartment_id = args.resource_compartment_id or scan_root_compartment_id

    # --log-group-* remains supported as a shared destination. New runs without
    # supplied resources use separate managed groups for bucket and flow logs.
    legacy_log_group_id = args.log_group_id
    legacy_log_group_name = args.log_group_name
    bucket_log_group_id = None
    flow_log_group_id = None
    capture_filter_id = None
    remediate_buckets = not args.skip_buckets and (bucket_target_ids is None or bool(bucket_target_ids))
    remediate_subnets = not args.skip_subnets and (subnet_target_ids is None or bool(subnet_target_ids))
    if args.bucket_findings_csv and not bucket_target_ids:
        print("[SKIP] CIS 4.17 CSV contains no non-empty bucket IDs; no bucket resources will be created.")
    if args.subnet_findings_csv and not subnet_target_ids:
        print("[SKIP] CIS 4.13 CSV contains no non-empty subnet IDs; no flow-log resources will be created.")

    if remediate_buckets:
        bucket_log_group_id = resolve_or_create_log_group(
            logging_client,
            args.bucket_log_group_id or legacy_log_group_id,
            args.bucket_log_group_name or legacy_log_group_name,
            args.bucket_log_group_compartment_id or args.log_group_compartment_id or resource_compartment_id,
            "cis-object-storage-logs",
            args.dry_run,
        )
    if remediate_subnets:
        flow_log_group_id = resolve_or_create_log_group(
            logging_client,
            args.flow_log_group_id or legacy_log_group_id,
            args.flow_log_group_name or legacy_log_group_name,
            args.flow_log_group_compartment_id or args.log_group_compartment_id or resource_compartment_id,
            "cis-vcn-flow-logs",
            args.dry_run,
        )
        capture_filter_id = resolve_or_create_capture_filter(
            virtual_network_client,
            args.subnet_capture_filter_id,
            resource_compartment_id,
            args.capture_filter_name,
            args.flow_log_sampling_interval,
            args.dry_run,
        )
    existing_logs = build_log_indexes(logging_client, compartment_ids)
    matched_bucket_ids: Set[str] = set()
    matched_subnet_ids: Set[str] = set()

    print(f"Scanning {len(compartment_ids)} compartment(s).")

    for compartment_id in compartment_ids:
        print(f"\n== Compartment {compartment_id} ==")
        if args.show_log_categories:
            show_log_categories(logging_client, compartment_id)

        bucket_logs = []
        subnet_logs = []
        if remediate_buckets:
            bucket_logs = desired_bucket_logs(
                object_storage_client,
                namespace,
                compartment_id,
                bucket_log_group_id,
                args.bucket_service,
                split_csv(args.bucket_categories),
                bucket_target_ids,
                matched_bucket_ids,
            )
        if remediate_subnets:
            subnet_logs = desired_subnet_logs(
                virtual_network_client,
                compartment_id,
                flow_log_group_id,
                args.subnet_flow_service,
                split_csv(args.subnet_flow_categories),
                capture_filter_id,
                subnet_target_ids,
                matched_subnet_ids,
            )

        print(f"Found {len(bucket_logs)} desired bucket logs and {len(subnet_logs)} desired subnet flow logs.")
        remediate(logging_client, bucket_logs + subnet_logs, existing_logs, args.dry_run)

    if bucket_target_ids is not None:
        missing_bucket_ids = bucket_target_ids - matched_bucket_ids
        if missing_bucket_ids:
            print(f"[WARN] {len(missing_bucket_ids)} bucket finding ID(s) were not found in the scan scope/region.")
    if subnet_target_ids is not None:
        missing_subnet_ids = subnet_target_ids - matched_subnet_ids
        if missing_subnet_ids:
            print(f"[WARN] {len(missing_subnet_ids)} subnet finding ID(s) were not found in the scan scope/region.")

    return 0


def main() -> int:
    args = parse_args()
    if args.skip_buckets and args.bucket_findings_csv:
        raise RuntimeError("Do not combine --skip-buckets with --bucket-findings-csv.")
    if args.skip_subnets and args.subnet_findings_csv:
        raise RuntimeError("Do not combine --skip-subnets with --subnet-findings-csv.")

    config = load_config(args)
    if not args.all_regions:
        return run_region(args, config)

    regional_resource_ids = (
        args.log_group_id,
        args.bucket_log_group_id,
        args.flow_log_group_id,
        args.subnet_capture_filter_id,
    )
    if any(regional_resource_ids):
        raise RuntimeError(
            "--all-regions cannot be used with Log Group or capture-filter OCIDs because those resources are regional. "
            "Omit the OCIDs to auto-create/reuse resources by name in each region."
        )

    tenancy_id = args.tenancy_id or config["tenancy"]
    identity_client = oci.identity.IdentityClient(config)
    subscriptions = oci.pagination.list_call_get_all_results(
        identity_client.list_region_subscriptions,
        tenancy_id,
    ).data
    subscribed_regions = {subscription.region_name for subscription in subscriptions if subscription.status == "READY"}
    csv_regions = set()
    if args.bucket_findings_csv:
        csv_regions.update(load_finding_regions(args.bucket_findings_csv, "CIS 4.17"))
    if args.subnet_findings_csv:
        csv_regions.update(load_finding_regions(args.subnet_findings_csv, "CIS 4.13"))
    if csv_regions:
        unavailable_regions = csv_regions - subscribed_regions
        if unavailable_regions:
            print(
                f"[WARN] Skipping {len(unavailable_regions)} CSV region(s) not in READY tenancy subscriptions.",
                file=sys.stderr,
            )
        regions = sorted(csv_regions & subscribed_regions)
    else:
        regions = sorted(subscribed_regions)
    if not regions:
        raise RuntimeError("No matching READY region subscriptions were found for this tenancy.")

    failures = 0
    print(f"Running remediation in {len(regions)} region(s).")
    for region in regions:
        regional_config = dict(config)
        regional_config["region"] = region
        print(f"\n{'=' * 12} Region {region} {'=' * 12}")
        try:
            run_region(args, regional_config)
        except (RuntimeError, ServiceError) as exc:
            failures += 1
            print(f"[ERROR] Region {region} was not remediated: {exc}", file=sys.stderr)

    if failures:
        print(f"[WARN] Remediation failed in {failures} region(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except ServiceError as exc:
        print(f"OCI API error: {exc.status} {exc.code}: {exc.message}", file=sys.stderr)
        raise SystemExit(1)
