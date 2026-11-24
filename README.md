# OCI Logging Remediation

`oci_logging_remediation.py` is a one-time OCI remediation utility for CIS checks **4.13** and **4.17**. It identifies missing service logs for Object Storage buckets and VCN subnets, then creates or enables the missing logs.

## What it remediates

| Resource | Log created when missing | Default category |
| --- | --- | --- |
| Object Storage bucket | Read and write service logs | `read`, `write` |
| VCN subnet | VCN Flow Log | `subnet` |

For a new subnet flow log, OCI requires a **FLOWLOG capture filter**. The script can use an existing filter or create one automatically. The filter OCID is sent as `capture_filter` in the log source parameters, with `enablementPointType` set to `Subnet`.

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
- OCI IAM permissions to inspect child compartments, list buckets/subnets/logs, and create or update logs in the selected scope.

## Scan scope

Without `--compartment-id`, the script scans the tenancy OCID from the OCI profile. With `--compartment-id`, it scans that compartment and all accessible active child compartments.

The supplied compartment ID can be either a tenancy OCID or any parent compartment OCID. Add `--current-compartment-only` to exclude child compartments.

### All subscribed regions

Use `--all-regions` to run the remediation in every tenancy region whose subscription is `READY`:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --all-regions \
  --dry-run
```

The script creates or reuses separate regional Log Groups and capture filters by name. Do not pass `--log-group-id`, `--bucket-log-group-id`, `--flow-log-group-id`, or `--subnet-capture-filter-id` with `--all-regions`: those OCIDs identify regional resources and cannot safely be reused in every region. You may pass the corresponding `--*-name` options when each region has resources with the same names.

When a findings CSV with a populated `region` column is also supplied, `--all-regions` processes only the READY regions named in that CSV rather than every subscribed region.

## Run it

Always start with a dry run. With no resource OCIDs supplied, it plans to create these resources in the scan-root compartment (or `--resource-compartment-id`):

- `cis-object-storage-logs` Log Group for CIS 4.17.
- `cis-vcn-flow-logs` Log Group for CIS 4.13.
- `cis-vcn-flow-log-capture-filter`, containing an enabled `ALL`/`INCLUDE` rule with sampling interval `1` (every flow).

### Single-region full scan (no CSV)

This checks every bucket and subnet in the selected compartment and its accessible child compartments, in only the specified region. The default bucket categories are `read,write`, which is the intended CIS 4.17 behavior.

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --region us-ashburn-1 \
  --bucket-categories read,write \
  --dry-run
```

Remove `--dry-run` only after confirming the planned actions.

To remediate only flow logs or only bucket logging:

```bash
python oci_logging_remediation.py --compartment-id <ocid> --skip-buckets --dry-run
python oci_logging_remediation.py --compartment-id <ocid> --skip-subnets --dry-run
```

## Resource modes

### Create all required resources

Omit all Log Group and capture-filter IDs. The script creates the resources listed above during a non-dry run.

On later runs, it reuses Log Groups and a FLOWLOG capture filter with the default (or user-supplied) resource names in the resource compartment. If multiple capture filters have the same name, pass `--subnet-capture-filter-id` to select the intended one.

```bash
python oci_logging_remediation.py --compartment-id <ocid>
```

### Reuse separate existing resources

Pass the resource OCIDs explicitly:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --bucket-log-group-id <bucket-log-group-ocid> \
  --flow-log-group-id <flow-log-group-ocid> \
  --subnet-capture-filter-id <flowlog-capture-filter-ocid> \
  --dry-run
```

### Reuse one shared Log Group

The original `--log-group-id` option remains available when both bucket and flow logs must be placed in the same existing Log Group:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --log-group-id <log-group-ocid> \
  --subnet-capture-filter-id <flowlog-capture-filter-ocid> \
  --dry-run
```

After reviewing any dry-run output, remove `--dry-run` to apply the changes.

## CIS findings CSV targeting

Use the CSV output from the CIS checker to limit remediation to findings rather than scanning and remediating every resource in scope:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --subnet-findings-csv /path/to/cis_Logging_and_Monitoring_4-13.csv \
  --bucket-findings-csv /path/to/cis_Logging_and_Monitoring_4-17.csv \
  --dry-run
```

To process only the regions represented by the CSV `region` column, add `--all-regions` and do not provide `--region`:

```bash
python oci_logging_remediation.py \
  --compartment-id <parent-compartment-or-tenancy-ocid> \
  --all-regions \
  --subnet-findings-csv /path/to/cis_Logging_and_Monitoring_4-13.csv \
  --bucket-findings-csv /path/to/cis_Logging_and_Monitoring_4-17.csv \
  --dry-run
```

- The 4.13 subnet CSV and 4.17 bucket CSV must include an `id` column containing OCI resource OCIDs. The script accepts only `ocid1.subnet.` IDs for 4.13 and `ocid1.bucket.` IDs for 4.17.
- When a findings CSV is supplied, only IDs in that file are eligible for remediation.
- Blank rows are ignored. A CSV with no non-empty IDs creates no Log Groups, capture filters, or logs for that control.
- The script warns when an ID from the CSV cannot be found in the chosen scan scope or configured OCI region.
- With `--all-regions`, rows are matched to the CSV `region` column when it is present, avoiding false “not found” warnings in other regions.
- When both controls are supplied as CSVs, the script scans only the `compartment_id` values listed in those CSVs instead of walking every child compartment. Without CSV input, it scans every resource in the selected compartment scope and configured region.
- CSV selection is currently “all listed findings.” Interactive per-resource selection can be added once a representative, non-sensitive sample is available.

### Useful options

| Option | Purpose |
| --- | --- |
| `--current-compartment-only` | Scan only the selected compartment. |
| `--all-regions` | Run in every READY subscribed tenancy region. Cannot be combined with `--region` or regional resource OCIDs. |
| `--skip-buckets` | Do not remediate Object Storage logs. |
| `--skip-subnets` | Do not remediate subnet flow logs; a capture-filter OCID is then not required. |
| `--resource-compartment-id <ocid>` | Where automatically created Log Groups and capture filter are placed. Defaults to the scan root. |
| `--bucket-log-group-id` / `--flow-log-group-id` | Separate existing destinations for bucket and flow logs. |
| `--bucket-log-group-name` / `--flow-log-group-name` | Reuse a same-named Log Group in the specified resource compartment. |
| `--log-group-id <ocid>` | One shared existing destination for both types (legacy compatibility). |
| `--subnet-capture-filter-id <ocid>` | Existing FLOWLOG capture filter; otherwise one is created. |
| `--capture-filter-name <name>` | Name of a FLOWLOG capture filter to reuse or create. |
| `--subnet-findings-csv <path>` | CIS 4.13 export; remediate only listed subnet OCIDs. |
| `--bucket-findings-csv <path>` | CIS 4.17 export; remediate only listed bucket OCIDs. |
| `--bucket-categories read,write` | Object Storage categories to enable. Default is `read,write`. |
| `--flow-log-sampling-interval <1-100000>` | Sampling interval for an auto-created capture filter. `1` captures every flow. |
| `--show-log-categories` | Print services/categories available in each compartment. Useful if OCI rejects a default category. |
| `--region <region>` | Override the OCI profile region. |
| `--profile <profile>` / `--config-file <path>` | Use a non-default OCI CLI profile or config file. |

## Interpreting output

| Output | Meaning |
| --- | --- |
| `[OK] Logging already enabled` | A matching log exists and is enabled; no change is made. |
| `[DRY-RUN] Would enable disabled log` | An existing log would be enabled in a non-dry run. |
| `[DRY-RUN] Would create service log` | No matching log was found; a non-dry run would create it. |
| `[ENABLE] Existing disabled log` | An existing log was enabled. |
| `[CREATE] Service log` | A new service log was created. |

## Troubleshooting

### `AttributeError: 'NoneType' object has no attribute 'id'` after Log Group creation

Use the current script version. OCI Logging creates Log Groups asynchronously and returns no Log Group object in the immediate create response. The script now waits for the associated work request and resolves the newly created Log Group before creating logs. A retry safely reuses a Log Group that may have been created before an earlier script run stopped.

### `Invalid parameter 'compartmentId must be tenancy ocid...'`

Use the current version of the script. It walks the compartment hierarchy one level at a time, allowing `--compartment-id` to be a normal parent-compartment OCID as well as a tenancy OCID.

### `409 Conflict: A log in the log group already uses this display name`

Use the current version, which adds a subnet-OCID suffix to newly generated subnet log names. If the error persists, the Log Group already contains a log with the same service/resource/category combination. Inspect the existing log rather than creating another one.

### OCI rejects a service or category

Run a dry run with `--show-log-categories`, then pass the values OCI reports using `--bucket-service`, `--bucket-categories`, `--subnet-flow-service`, or `--subnet-flow-categories`.

