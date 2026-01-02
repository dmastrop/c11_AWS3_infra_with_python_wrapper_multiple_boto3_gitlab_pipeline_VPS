# utils_sg_state.py
# Helper functions for the stateful SG rule system used across module2, module2e, and module2f.
#
# This module centralizes all Security Group (SG) state-management helpers:
#   - Loading previous SG_RULES state from S3 (pipeline N)
#   - Saving current SG_RULES state to S3 (pipeline N+1)
#   - Computing delta_delete (rules removed between pipelines)
#   - Applying SG rule adds/deletes to AWS
#   - Drift detection helpers for module2 main()
#   - Replay helpers used by module2e during ghost-node resurrection
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
#       apply_sg_rules_add,
#       apply_sg_rules_delete,
#       detect_sg_drift_with_delta,
#       replay_sg_rules_for_resurrection
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
# NOTE:
#   This file intentionally contains *no business logic yet*.
#   Only function signatures + extensive comments + docstrings.
#   The logic will be filled in  during implementation.
#
# ---------------------------------------------------------------------------

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
    pass



# ===========================================================================
# 2. load_delta_delete__from_s3()
# ===========================================================================

def load_delta_delete_from_s3(bucket, key="state/sg_rules/delta_delete.json"):
    """
    Load the delta_delete manifest from S3.

    This file contains the rules that were removed in the previous pipeline run.
    Module2e uses this to delete stale rules after rebooting ghost nodes.

    Returns:
        - A list/dict of rules to delete
        - Or {} if the file does not exist (e.g., first pipeline run)
    """
    s3 = boto3.client("s3")

    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        body = resp["Body"].read().decode("utf-8")
        return json.loads(body)
    except s3.exceptions.NoSuchKey:
        print(f"[utils_sg_state] No delta_delete file found at {key}. Returning empty delta.")
        return {}
    except Exception as e:
        print(f"[utils_sg_state] Error loading delta_delete from S3: {e}")
        return {}


# ===========================================================================
# 3. save_current_sg_rules_to_s3()
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
# 4. save_delta_delete_to_s3()
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
    pass



# ===========================================================================
# 5. compute_delta_delete()
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
    """
    pass



# ===========================================================================
# 6. apply_sg_rules_add()
# ===========================================================================

def apply_sg_rules_add(ec2, sg_id, rules):
    """
    Apply (add) ALL SG_RULES to the given security group.

    This is used in:
        • module2 (per-process SG rule application)
        • module2e (post-reboot SG replay)

    Behavior:
        - Must be idempotent (adding an existing rule should not error)
        - Must handle AWS throttling (retry logic will be added later)

    Parameters:
        ec2  : boto3 EC2 client
        sg_id (str): Security group ID
        rules (list): List of SG rule dicts to add
    """
    pass



# ===========================================================================
# 7. apply_sg_rules_delete()
# ===========================================================================

def apply_sg_rules_delete(ec2, sg_id, delta_delete):
    """
    Delete stale SG rules from AWS.

    delta_delete contains ONLY the rules that were removed between
    pipeline N and pipeline N+1.

    Behavior:
        - Must gracefully handle "rule not found" cases
        - Must be safe to call repeatedly
        - Must handle AWS throttling (retry logic added later)

    Parameters:
        ec2  : boto3 EC2 client
        sg_id (str): Security group ID
        delta_delete (list): Rules to delete
    """
    pass



# ===========================================================================
# 8. detect_sg_drift_with_delta()
# ===========================================================================

def detect_sg_drift_with_delta(ec2, sg_id, current_rules, delta_delete):
    """
    Perform drift detection using BOTH:
        • current_rules (desired state)
        • delta_delete (rules that should have been removed)

    Drift categories:
        - Missing rules (should be present but aren't)
        - Stale rules (should have been deleted but still exist)
        - Unexpected rules (optional: rules not in desired state)

    Parameters:
        ec2  : boto3 EC2 client
        sg_id (str): Security group ID
        current_rules (list): SG_RULES for pipeline N+1
        delta_delete (list): Rules expected to be deleted

    Returns:
        dict containing:
            {
                "missing": [...],
                "stale": [...],
                "unexpected": [...]
            }

    Notes:
        - This replaces the old detect_sg_drift() in module2.
        - This is the authoritative drift detector for the new design.
    """
    pass



# ===========================================================================
# 9. replay_sg_rules_for_resurrection()
# ===========================================================================

def replay_sg_rules_for_resurrection(ec2, sg_id, current_rules, delta_delete):
    """
    Replay SG rules on rebooted nodes (module2e).

    Steps:
        1. Reapply ALL current_rules (idempotent)
        2. Delete ALL delta_delete rules
        3. Ensure SG converges to desired state

    This is simpler than module2 because module2e is NOT multiprocessing.

    Parameters:
        ec2  : boto3 EC2 client
        sg_id (str): Security group ID
        current_rules (list): SG_RULES for pipeline N+1
        delta_delete (list): Rules to delete
    """
    pass

