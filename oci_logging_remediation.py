#!/usr/bin/env python3
"""
OCI logging remediation script.

Checks:
  1. Object Storage buckets: enables read and write service logs.
  2. Subnets: enables VCN flow logs.

Requirements:
  pip install oci

Examples:
  python oci_logging_remediation.py \
    --log-group-id ocid1.loggroup.oc1..aaaa... \
    --dry-run

  python oci_logging_remediation.py \
    --log-group-name existing-security-logs \
    --log-group-compartment-id ocid1.compartment.oc1..aaaa...
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import oci
from oci.exceptions import ServiceError


OBJECT_STORAGE_SERVICE = "objectstorage"
OBJECT_STORAGE_CATEGORIES = ("read", "write")

# OCI VCN Flow Logs are service logs. In most tenancies the service is "flowlogs"
# and the category is "all". If your tenancy exposes different values, run with
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
    parser.add_argument("--region", help="Override region from OCI config.")
    log_group = parser.add_mutually_exclusive_group(required=True)
    log_group.add_argument("--log-group-id", help="Existing log group OCID where missing service logs will be created.")
    log_group.add_argument("--log-group-name", help="Existing log group name where missing service logs will be created.")
    parser.add_argument(
        "--log-group-compartment-id",
        help="Compartment OCID containing --log-group-name. Recommended when using --log-group-name.",
    )
    parser.add_argument(
        "--current-compartment-only",
        action="store_true",
        help="Only scan the selected compartment, not its child compartments.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only report actions. Do not create or enable logs.")
    parser.add_argument("--skip-buckets", action="store_true", help="Do not check or remediate bucket logs.")
    parser.add_argument("--skip-subnets", action="store_true", help="Do not check or remediate subnet flow logs.")
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
        help="Existing FLOWLOG capture filter OCID to attach to every subnet flow log.",
    )
    parser.add_argument(
        "--show-log-categories",
        action="store_true",
        help="Print available Logging service/category values for each compartment before remediation.",
    )
    return parser.parse_args()


def split_csv(value: str) -> Tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


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


def resolve_existing_log_group(logging_client, args: argparse.Namespace, compartment_ids: List[str]) -> str:
    if args.log_group_id:
        return args.log_group_id

    search_compartments = [args.log_group_compartment_id] if args.log_group_compartment_id else compartment_ids
    matches = []
    for compartment_id in search_compartments:
        groups = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups,
            compartment_id=compartment_id,
            display_name=args.log_group_name,
        ).data
        matches.extend(group for group in groups if group.lifecycle_state != "DELETED")

    if not matches:
        searched = args.log_group_compartment_id or "all scanned compartments"
        raise RuntimeError(f"Existing log group '{args.log_group_name}' was not found in {searched}.")

    if len(matches) > 1:
        print(f"Found multiple existing log groups named '{args.log_group_name}':", file=sys.stderr)
        for group in matches:
            print(f"  {group.id} in compartment {group.compartment_id}", file=sys.stderr)
        raise RuntimeError("Use --log-group-id or --log-group-compartment-id to select one log group.")

    group = matches[0]
    print(f"Using existing log group '{group.display_name}' -> {group.id}")
    return group.id


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


def desired_bucket_logs(
    object_storage_client,
    namespace: str,
    compartment_id: str,
    log_group_id: str,
    service: str,
    categories: Tuple[str, ...],
) -> List[DesiredLog]:
    desired = []
    for bucket in list_buckets(object_storage_client, namespace, compartment_id):
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
) -> List[DesiredLog]:
    desired = []
    for subnet in list_subnets(virtual_network_client, compartment_id):
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


def main() -> int:
    args = parse_args()
    if not args.skip_subnets and not args.subnet_capture_filter_id:
        raise RuntimeError("--subnet-capture-filter-id is required unless --skip-subnets is used.")
    config = load_config(args)

    identity_client = oci.identity.IdentityClient(config)
    logging_client = oci.logging.LoggingManagementClient(config)
    object_storage_client = oci.object_storage.ObjectStorageClient(config)
    virtual_network_client = oci.core.VirtualNetworkClient(config)

    tenancy_id = args.tenancy_id or config["tenancy"]
    scan_root_compartment_id = args.compartment_id or tenancy_id
    namespace = object_storage_client.get_namespace().data
    compartment_ids = active_compartments(
        identity_client,
        scan_root_compartment_id,
        args.current_compartment_only,
    )
    log_group_id = resolve_existing_log_group(logging_client, args, compartment_ids)
    existing_logs = build_log_indexes(logging_client, compartment_ids)

    print(f"Scanning {len(compartment_ids)} compartment(s).")

    for compartment_id in compartment_ids:
        print(f"\n== Compartment {compartment_id} ==")
        if args.show_log_categories:
            show_log_categories(logging_client, compartment_id)

        bucket_logs = []
        subnet_logs = []
        if not args.skip_buckets:
            bucket_logs = desired_bucket_logs(
                object_storage_client,
                namespace,
                compartment_id,
                log_group_id,
                args.bucket_service,
                split_csv(args.bucket_categories),
            )
        if not args.skip_subnets:
            subnet_logs = desired_subnet_logs(
                virtual_network_client,
                compartment_id,
                log_group_id,
                args.subnet_flow_service,
                split_csv(args.subnet_flow_categories),
                args.subnet_capture_filter_id,
            )

        print(f"Found {len(bucket_logs)} desired bucket logs and {len(subnet_logs)} desired subnet flow logs.")
        remediate(logging_client, bucket_logs + subnet_logs, existing_logs, args.dry_run)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ServiceError as exc:
        print(f"OCI API error: {exc.status} {exc.code}: {exc.message}", file=sys.stderr)
        raise SystemExit(1)
