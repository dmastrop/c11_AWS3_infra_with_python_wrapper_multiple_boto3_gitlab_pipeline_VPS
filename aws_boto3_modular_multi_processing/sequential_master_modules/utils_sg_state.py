# utils_sg_state.py
# Helper functions for the stateful SG rule system used across module2, module2e, and module2f.
#
# This module centralizes all Security Group (SG) state-management helpers:
#   - Loading previous SG_RULES state from S3 (pipeline N)
#   - Saving current SG_RULES state to S3 (pipeline N+1)
#   - Computing delta_delete (rules removed between pipelines)
#   - Drift detection helpers for module2 main()
#
# These helpers are intentionally isolated from module2 to:
#   - Keep module2 lean and focused on orchestration + multiprocessing
#   - Allow module2e/module2f to reuse the exact same SG logic
#   - Ensure deterministic, audit-friendly SG state transitions across pipelines
#
# Import path (package-aware):
#   from sequential_master_modules.utils_sg_state import (
#       load_previous_sg_rules_from_s3,
#       save_current_sg_rules_to_s3,
#       save_delta_delete_to_s3,
#       compute_delta_delete,
#       detect_sg_drift_with_delta,
#   )
#
# NOTE:
#   - This file contains *no* orchestration logic.
#   - It is purely functional and stateless except for S3 I/O.
#   - All SG_RULES normalization is handled here to keep module2 clean.


# utils_sg_state.py
# ---------------------------------------------------------------------------
# Stateful Security Group (SG) Rule Management Utilities
#
# This module contains ALL helper functions required for the new stateful
# SG-rule system used by:
#
#   - module2  (multiprocessing SG rule application)
#   - module2e (post-reboot SG rule replay for ghost nodes)
#   - module2f (resurrection install logic)
#
# These helpers implement the *stateful* SG design:
#
#   • SG_RULES (authoritative desired state)
#   • previous_rules (pipeline N state from S3)
#   • delta_delete (rules removed between pipelines)
#   • drift detection using SG_RULES + delta_delete
#   • replay logic for module2e
#
# ---------------------------------------------------------------------------



# IMPORTANT:
#   - module2 uses latest.json as "previous" (pipeline N)
#   - module2 main() overwrites latest.json with SG_RULES (pipeline N+1)
#   - module2e uses latest.json as "current" (pipeline N+1)





import boto3
import json
import os


# ===========================================================================
# 1. load_previous_sg_rules_from_s3()
# ===========================================================================

def load_previous_sg_rules_from_s3(bucket, key="state/sg_rules/latest.json"):
    """
    Load the SG_RULES manifest from the previous pipeline (pipeline N).

    This file is stored in S3 and represents the authoritative SG_RULES
    from the *last* pipeline run. It is used by module2 to compute:

        delta_delete = previous_rules - current_rules

    Behavior:
        • If the file exists → return parsed JSON (list of rule dicts)
        • If the file does NOT exist → return {} (first pipeline run)

    Parameters:
        bucket (str): S3 bucket name
        key (str): S3 key for the manifest (default: latest.json)

    Returns:
        dict or list: previous SG rules, or {} if not found

    Notes:
        - This function must NEVER throw an exception for missing files.
        - Module2 relies on {} to indicate "no previous state".
    """
    import boto3
    import json

    s3 = boto3.client("s3")

    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read().decode("utf-8")
        rules = json.loads(body)

        if isinstance(rules, list):
            print(f"[utils_sg_state] Loaded previous SG_RULES from s3://{bucket}/{key}")
            return rules

        print(f"[utils_sg_state] WARNING: SG_RULES file exists but is not a list — returning empty dict")
        return {}

    except s3.exceptions.NoSuchKey:
        print(f"[utils_sg_state] No previous SG_RULES found in S3 — returning empty dict")
        return {}

    except Exception as e:
        print(f"[utils_sg_state] ERROR loading previous SG_RULES from S3: {e}")
        return {}






# ===========================================================================
# 2. save_current_sg_rules_to_s3()
# ===========================================================================

def save_current_sg_rules_to_s3(bucket, rules, key="state/sg_rules/latest.json"):
    """
    Save the *current* pipeline's SG_RULES (pipeline N+1) to S3.

    This overwrites the previous manifest and becomes the new
    authoritative state for the next pipeline run.

    Parameters:
        bucket (str): S3 bucket name
        rules (list): List of SG rule dicts (SG_RULES)
        key (str): S3 key to write to

    Notes:
        - This is called AFTER delta_delete is computed.
        - This file is always overwritten (no versioning needed).
    """
    import boto3
    import json

    s3 = boto3.client("s3")

    try:
        body = json.dumps(rules, indent=2)
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
        print(f"[utils_sg_state] Uploaded SG_RULES to s3://{bucket}/{key}")
    except Exception as e:
        print(f"[utils_sg_state] ERROR saving SG_RULES to S3: {e}")


# ===========================================================================
# 3. save_delta_delete_to_s3()
# ===========================================================================

def save_delta_delete_to_s3(bucket, delta, key="state/sg_rules/delta_delete.json"):
    """
    Save the delta_delete list to S3.

    delta_delete is defined as:

        previous_rules - current_rules

    These are the rules that must be removed from AWS SGs.

    Module2e uses this file to delete stale rules after rebooting ghost nodes.

    Parameters:
        bucket (str): S3 bucket name
        delta (list): List of rule dicts to delete
        key (str): S3 key to write to
    """

    import boto3
    import json

    s3 = boto3.client("s3")

    try:
        body = json.dumps(delta, indent=2)
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
        print(f"[utils_sg_state] Uploaded delta_delete → s3://{bucket}/{key}")
        print(f"[utils_sg_state] Delta count saved: {len(delta)}")
    except Exception as e:
        print(f"[utils_sg_state] ERROR saving delta_delete to S3: {e}")


# ===========================================================================
# 4. compute_delta_delete()
# ===========================================================================

def compute_delta_delete(previous_rules, current_rules):
    """
    Compute the delta_delete set:

        delta_delete = previous_rules - current_rules

    This function must:
        • Normalize rule formats (tuple or dict)
        • Compare previous vs current
        • Return only rules that were removed

    Parameters:
        previous_rules (list): SG rules from pipeline N
        current_rules  (list): SG_RULES from pipeline N+1

    Returns:
        list: rules that must be deleted from AWS SGs

    Notes:
        - delta_add is intentionally NOT computed.
        - Module2 always reapplies ALL SG_RULES, so delta_add is irrelevant.

    Rules are dicts of the form:
        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"}

    Normalization is done inline (no helper function).
    """

    def normalize(rule):
        """Inline normalization → convert rule dict to a comparable tuple."""
        try:
            return (
                rule.get("protocol"),
                int(rule.get("port")),
                rule.get("cidr")
            )
        except Exception:
            # If rule is malformed, return None so it never matches
            return None

    # Normalize both sets
    prev_norm = {normalize(r): r for r in previous_rules if normalize(r)}
    curr_norm = {normalize(r): r for r in current_rules if normalize(r)}

    # Compute delta: rules present before but not now
    delta_norm = set(prev_norm.keys()) - set(curr_norm.keys())

    # Convert back to full rule dicts
    delta_delete = [prev_norm[n] for n in delta_norm]

    print(f"[utils_sg_state] compute_delta_delete → {len(delta_delete)} rules to delete")

    # Print each rule for forensic clarity
    for rule in delta_delete:
        print(f"[utils_sg_state] DELTA_DELETE → {rule}")

    return delta_delete


# ===========================================================================
# 5. detect_sg_drift_with_delta()
# ===========================================================================

def detect_sg_drift_with_delta(ec2, sg_id, current_rules, delta_delete):
    """
    SG_STATE — STEP 5: Drift Detection
    ----------------------------------

    This function compares:
        • SG_RULES (current desired state)
        • delta_delete (rules that SHOULD have been deleted)
        • actual AWS SG rules

    It computes FOUR drift categories.

    -------------------------------------------------------------------------
    FULL EXAMPLE CONTEXT (for clarity)
    -------------------------------------------------------------------------

    SG_RULES (current desired state):
        {22, 80, 8080, 5001, 5002, 5003}

    Previous pipeline state (latest.json from module2):
        {22, 80, 8080, 5001, 5002, 5003, 5004}

    delta_delete.json (rules that SHOULD be deleted this pipeline):
        {5004}

    Actual AWS SG rules at runtime:
        {22, 8080, 5001, 5002, 5003, 5004, 443, 9999}

    Observations:
        • Port 80 is missing on AWS (unexpected)
        • Port 5004 still exists (revoke failed)
        • Ports 443 and 9999 exist on AWS but are not part of SG_RULES
          and not part of delta_delete → these are ignored

    -------------------------------------------------------------------------
    FORMULAS (explicit)
    -------------------------------------------------------------------------

    Let:
        desired = SG_RULES (normalized)
        delta   = delta_delete (normalized)
        actual  = AWS SG rules (normalized)

    1. drift_missing:
           desired - actual
       Meaning:
           "Ports that SHOULD be on AWS but are NOT."
       Example:
           {80}

    2. drift_extra_raw:
           actual - desired
       Meaning:
           "All ports AWS has that SG_RULES does NOT include."
       Example:
           {5004, 443, 9999}

    3. drift_extra_filtered:
           { r ∈ drift_extra_raw | r ∈ delta_delete }
       Meaning:
           "Ports that ARE on AWS but SHOULD have been deleted."
           The math above will simply get the intersection between drift_extra_raw and delta_delete (in the example: 5004)
       Example:
           {5004}

    4. drift_ignored:
           drift_extra_raw - drift_extra_filtered
       Meaning:
           "Ports AWS has that we IGNORE because they are not part of SG_STATE."
       Example:
           {443, 9999}

    -------------------------------------------------------------------------
    """

    print(f"[utils_sg_state] Starting drift detection for SG {sg_id}")

    # ------------------------------------------------------------
    # STEP 1 — Normalize SG_RULES (desired state)
    # ------------------------------------------------------------
    desired = {
        (r["protocol"], int(r["port"]), r["cidr"])
        for r in current_rules
    }

    # ------------------------------------------------------------
    # STEP 2 — Normalize delta_delete (rules that SHOULD be removed)
    # ------------------------------------------------------------
    delta = {
        (r["protocol"], int(r["port"]), r["cidr"])
        for r in delta_delete
    }

    # ------------------------------------------------------------
    # STEP 3 — Query AWS for actual SG rules
    # ------------------------------------------------------------
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = resp["SecurityGroups"][0]
    except Exception as e:
        print(f"[utils_sg_state] ERROR: Unable to query SG {sg_id}: {e}")
        return {
            "drift_missing": [],
            "drift_extra_filtered": [],
            "drift_extra_raw": [],
            "drift_ignored": []
        }

    actual = set()
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")

        if from_p is None or to_p is None:
            continue

        for rng in perm.get("IpRanges", []):
            cidr = rng.get("CidrIp")
            if cidr:
                actual.add((proto, int(from_p), cidr))

    # ------------------------------------------------------------
    # STEP 4 — Apply formulas to compute drift categories
    # ------------------------------------------------------------

    drift_missing = sorted(desired - actual)
    drift_extra_raw = sorted(actual - desired)
    drift_extra_filtered = sorted([r for r in drift_extra_raw if r in delta])
    drift_ignored = sorted(set(drift_extra_raw) - set(drift_extra_filtered))

    # ------------------------------------------------------------
    # STEP 5 — Print results for GitLab logs
    # ------------------------------------------------------------
    print(f"[utils_sg_state] Drift results for SG {sg_id}:")
    print(f"[utils_sg_state]   drift_missing  (Ports that SHOULD be on AWS but are NOT)                                  = {drift_missing}")
    print(f"[utils_sg_state]   drift_extra_filtered (Ports that ARE on AWS but SHOULD have been deleted)                 = {drift_extra_filtered}")
    print(f"[utils_sg_state]   drift_extra_raw (All ports AWS has that SG_RULES does NOT include)                        = {drift_extra_raw}")
    print(f"[utils_sg_state]   drift_ignored (Ports AWS has that we IGNORE because they are not part of SG_STATE)        = {drift_ignored}")

    # ------------------------------------------------------------
    # STEP 6 — Return structured drift report
    # ------------------------------------------------------------
    return {
        "drift_missing (Ports that SHOULD be on AWS but are NOT)": drift_missing,
        "drift_extra_filtered (Ports that ARE on AWS but SHOULD have been deleted)": drift_extra_filtered,
        "drift_extra_raw (All ports AWS has that SG_RULES does NOT include)": drift_extra_raw,
        "drift_ignored (Ports AWS has that we IGNORE because they are not part of SG_STATE)": drift_ignored
    }


