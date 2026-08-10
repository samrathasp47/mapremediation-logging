# OCI Logging Remediation

`oci_logging_remediation.py` is a one-time OCI remediation utility. It identifies missing service logs for Object Storage buckets and VCN subnets, then creates or enables the missing logs in an existing OCI Log Group.

## What it remediates

| Resource | Log created when missing | Default category |
| --- | --- | --- |
| Object Storage bucket | Read and write service logs | `read`, `write` |
| VCN subnet | VCN Flow Log | `subnet` |

For a new subnet flow log, the script requires an existing OCI **FLOWLOG capture filter**. The filter OCID is sent as `capture_filter` in the log source parameters, with `enablementPointType` set to `Subnet`.

## Safe behaviour

The script is additive-only for existing logs:

- An existing, enabled matching log is left unchanged.
- An existing, disabled matching log is enabled; its capture filter and other configuration are left unchanged.
- A missing log is created and enabled.
- A supplied capture-filter OCID is used only for newly created subnet flow logs.

Subnet log display names include a suffix from the subnet OCID. This prevents name collisions when different compartments contain subnets with the same display name.

## Prerequisites

- Python 3
- OCI Python SDK:

  ```bash
  pip install oci
  ```

- A working OCI configuration, normally at `~/.oci/config`, or an alternate file/profile passed with `--config-file` and `--profile`.
- An existing OCI Log Group.
- An existing capture filter of type `FLOWLOG` when subnet remediation is enabled.
- OCI IAM permissions to inspect child compartments, list buckets/subnets/logs, and create or update logs in the selected scope.

## Scan scope

Without `--compartment-id`, the script scans the tenancy OCID from the OCI profile. With `--compartment-id`, it scans that compartment and all accessible active child compartments.

The supplied compartment ID can be either a tenancy OCID or any parent compartment OCID. Add `--current-compartment-only` to exclude child compartments.

## Run it

Always start with a dry run:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --log-group-id <log-group-ocid> \
  --subnet-capture-filter-id <flowlog-capture-filter-ocid> \
  --dry-run
```

After reviewing the output, remove `--dry-run` to apply the changes:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --log-group-id <log-group-ocid> \
  --subnet-capture-filter-id <flowlog-capture-filter-ocid>
```

### Useful options

| Option | Purpose |
| --- | --- |
| `--current-compartment-only` | Scan only the selected compartment. |
| `--skip-buckets` | Do not remediate Object Storage logs. |
| `--skip-subnets` | Do not remediate subnet flow logs; a capture-filter OCID is then not required. |
| `--log-group-name <name>` | Select an existing Log Group by name instead of OCID. Use with `--log-group-compartment-id` when possible. |
| `--show-log-categories` | Print services/categories available in each compartment. Useful if OCI rejects a default category. |
| `--region <region>` | Override the OCI profile region. |

## Interpreting output

| Output | Meaning |
| --- | --- |
| `[OK] Logging already enabled` | A matching log exists and is enabled; no change is made. |
| `[DRY-RUN] Would enable disabled log` | An existing log would be enabled in a non-dry run. |
| `[DRY-RUN] Would create service log` | No matching log was found; a non-dry run would create it. |
| `[ENABLE] Existing disabled log` | An existing log was enabled. |
| `[CREATE] Service log` | A new service log was created. |

## Troubleshooting

### `Invalid parameter 'compartmentId must be tenancy ocid...'`

Use the current version of the script. It walks the compartment hierarchy one level at a time, allowing `--compartment-id` to be a normal parent-compartment OCID as well as a tenancy OCID.

### `409 Conflict: A log in the log group already uses this display name`

Use the current version, which adds a subnet-OCID suffix to newly generated subnet log names. If the error persists, the Log Group already contains a log with the same service/resource/category combination. Inspect the existing log rather than creating another one.

### OCI rejects a service or category

Run a dry run with `--show-log-categories`, then pass the values OCI reports using `--bucket-service`, `--bucket-categories`, `--subnet-flow-service`, or `--subnet-flow-categories`.

