import json
import os
from datetime import datetime
import boto3

## Imports from shared utilities (utils.py)
#from utils import resolve_instance_id, _extract_instance_id

# Shared helper functions live in sequential_master_modules/utils.py
from sequential_master_modules.utils import (
    resolve_instance_id,
    _extract_instance_id,
    log_ghost_context,
    reboot_instance,
    health_check_instance
)


# per the docker container volume mount. This maps to the logs directory on gitlab artifact logs.(.gitlab-ci.yml)
      # Phase3 log files
      #- logs/command_plan.json  # module2
      #- logs/resurrection_module2e_registry.json  # module2e
      #- logs/aggregate_resurrection_stats_module2e.json  # module2e
LOG_DIR = "/aws_EC2/logs"
STATISTICS_DIR = os.path.join(LOG_DIR, "statistics")




def load_json(filename, log_dir=LOG_DIR):
    path = os.path.join(log_dir, filename)
    print(f"[module2e_logging] Loading JSON artifact from {path}")
    with open(path, "r") as f:
        return json.load(f)

def write_json(filename, data, log_dir=LOG_DIR):
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[module2e_logging] Wrote JSON artifact to {path}")





##### see utils.py file
##### add the _extract_instance_id function that is used by teh resolve_instance_id function below. These are both from module2f
#def _extract_instance_id(describe_resp):
#    """
#    Helper to pull InstanceId out of AWS describe_instances response.
#    """
#    for r in describe_resp.get("Reservations", []):
#        for i in r.get("Instances", []):
#            iid = i.get("InstanceId")
#            if iid: return iid
#    return None
#
#
##### This helper function is used for the InstanceId decison logic (in the ghost handler function process_ghost
#def resolve_instance_id(public_ip=None, private_ip=None, region=None):
#    """
#    Resolve the current InstanceId live from AWS.
#    - Prefer public IP lookup (most stable for resurrection).
#    - Fallback to private IP if public is missing.
#    - This ensures we always get the *current* instance_id, even if IPs were recycled.
#    """
#    session = boto3.Session(region_name=region or os.getenv("region_name"))
#    ec2 = session.client("ec2")
#
#    # Try public IP filter first
#    if public_ip:
#        resp = ec2.describe_instances(
#            Filters=[{"Name": "ip-address", "Values": [public_ip]}]
#        )
#        iid = _extract_instance_id(resp)
#        if iid: return iid
#
#    # Fallback: try private IP filter
#    if private_ip:
#        resp = ec2.describe_instances(
#            Filters=[{"Name": "network-interface.addresses.private-ip-address",
#                      "Values": [private_ip]}]
#        )
#        iid = _extract_instance_id(resp)
#        if iid: return iid
#
#    print(f"[module2f] InstanceId not found for IPs public={public_ip}, private={private_ip}")
#    return None


def normalize_resurrection_reason(entry, new_reason):
    # Convert string to list if needed
    if isinstance(entry.get("resurrection_reason"), str):
        entry["resurrection_reason"] = [entry["resurrection_reason"]]
    entry.setdefault("resurrection_reason", [])
    entry["resurrection_reason"].append(new_reason)

def process_idx1(entry, command_plan):
    # Ensure tags list exists
    entry.setdefault("tags", [])
    
    # Add skip flag so synthetic crash doesn’t fire again
    entry["tags"].append("skip_synthetic_future_crash_on_resurrection")
    
    normalize_resurrection_reason(entry, "Idx1 futures crash detected, requeued with full command set")
    
    # Prototype: replay full wrapped_commands. Placeholder for the actual callback to module2 to process the SSH connection and the
    # command execution using the thread logic, to resurrect the thread.
    entry["replayed_commands"] = command_plan["wrapped_commands"]   # the command set is actually added to the registry_entry 
    
    return entry

def process_generic(entry, command_plan):
    entry.setdefault("tags", [])
    normalize_resurrection_reason(entry, "Generic resurrection candidate, requeued with full command set")
    entry["replayed_commands"] = command_plan["wrapped_commands"]
    return entry


#def process_ghost(entry, command_plan):
#    entry.setdefault("tags", [])
#    normalize_resurrection_reason(entry, "Ghost entry: resurrection always attempted with full command set")
#    entry["pre_resurrection_reboot_required"] = True  # This is for module2f code. We want to reboot the node if it is a ghost prior to attemping resurrection
#    entry["replayed_commands"] = command_plan["wrapped_commands"]
#    return entry


#### Ghost ip handler:
#### Add decision logic for whether or not the InstanceId is available. The pre_resurrection_reboot_required is only required if the InstanceId is available
#### If the InstanceId is not available then set this to false. If it is avaiable set it to true
#### This uses the same InstanceId helper function resolve_instance_id from module2f
def process_ghost(entry, command_plan, region=None):
    entry.setdefault("tags", [])
    normalize_resurrection_reason(entry, "Ghost entry: resurrection always attempted with full command set")
    entry["replayed_commands"] = command_plan["wrapped_commands"]

    # Try to resolve InstanceId for this ghost
    instance_id = entry.get("instance_id")
    if not instance_id:
        instance_id = resolve_instance_id(
            public_ip=entry.get("public_ip"),
            private_ip=entry.get("private_ip"),
            region=region
        )

    # Set reboot flag based on whether InstanceId is available
    entry["pre_resurrection_reboot_required"] = bool(instance_id)

    # Ghost context tagging for synthetic ghosts. If there is no instance_id, set teh ghost context tag to no_instance_id. Ghost context tagging will help 
    # differentiate non-ghost thread issues with ghost issues not only for thread resurrection in module2f but also with Machine Learning analytics in Phase4
    if not instance_id:
        log_ghost_context(entry, "no_instance_id")

    # Add the calls to reboot_instance and health_check_instance for instance_id present case. The else ensures that instance_id will be present. Note for the 
    # instance_id present case the tag will be pre_resurrection_reboot_required: True
    else:
        # Real ghost → attempt reboot + health check
        reboot_ok = reboot_instance(instance_id, region=region)
        if not reboot_ok:
            log_ghost_context(entry, "reboot_failed")
            entry["status"] = "install_failed"
            return entry

        health_ok = health_check_instance(instance_id, region=region)
        if not health_ok:
            log_ghost_context(entry, "health_checks_not_ok")
            entry["status"] = "install_failed"
            return entry



    return entry



#### prototype code for resurrecting an idx1 futures crash thread using re-iteration of the complete command set (native_commands that
#### are in  strace wrapped form from module2).  Will decide on a more sreamlined approach once the prototype is tested.
#### Note the bucketization of the resurrection types. This will help in Phase4 ML

def main():
    registry = load_json("resurrection_gatekeeper_final_registry_module2d.json")
    
    command_plan = load_json("command_plan.json")

    # stats input lives in /aws_EC2/logs/statistics
    stats = load_json("aggregate_process_stats_gatekeeper_module2d.json", log_dir=STATISTICS_DIR)

    resurrection_registry = {}
    by_bucket = {}
    resurrected_total = 0


    ## DEPRECATED CODE:
    #for uuid, entry in registry.items():
    #    tags = entry.get("tags", [])
    #    #if "gatekeeper_blocked" in tags or "install_success_achieved_before_crash" in tags:
    #    #    continue
    #    #if "gatekeeper_resurrect" not in tags:
    #    #    continue

    #    # Simplified: only handle idx1 for prototype
    #    if "future_exception" in tags and "RuntimeError" in tags and "gatekeeper_resurrect" in tags:
    #        entry = process_idx1(entry, command_plan)
    #        resurrected_total += 1
    #        bucket = "idx1"
    #    
    #    # Create a bucket for the second type of futures crash
    #    elif "future_exception" in tags and "RuntimeError" in tags and "install_success_achieved_before_crash" in tags:
    #        bucket = "post_exec_future_crash"
    #    
    #    # This will cover gatekeeper_blocked, gatekeeper_resurrect NOT in tags:
    #    else:
    #        bucket = "generic"

    #    by_bucket.setdefault(bucket, {"candidates": 0, "resurrected": 0, "selected_for_resurrection": 0})
    #    #by_bucket.setdefault(bucket, {"candidates": 0, "resurrected": 0})
    #    by_bucket[bucket]["candidates"] += 1
    #    if bucket == "idx1":
    #        by_bucket[bucket]["selected_for_resurrection"] += 1


    #    resurrection_registry[uuid] = entry

    #Replace the above for block with the block below. The above block has several issues with the HYBRID futures crash case
    #and with the bucketization and the module2e registry file creation

    for uuid, entry in registry.items():
        tags = entry.get("tags", [])
        status = entry.get("status", "")

        if "future_exception" in tags and "RuntimeError" in tags and "gatekeeper_resurrect" in tags:
            entry = process_idx1(entry, command_plan)
            resurrected_total += 1
            bucket = "idx1"
            resurrection_registry[uuid] = entry

        elif "future_exception" in tags and "RuntimeError" in tags and "install_success_achieved_before_crash" in tags:
            bucket = "post_exec_future_crash"   # tracked, not resurrected

        elif status == "install_success":
            bucket = "already_install_success"  # tracked, not resurrected

        elif status == "ghost":
            bucket = "ghost"
            entry = process_ghost(entry, command_plan) # use the ghost handler process_ghost helper function
            resurrected_total += 1
            resurrection_registry[uuid] = entry
       
        # The rest are either install_failed or stub registry_entrys that will most likely need to be resurrected in accordance with module2d definition of
        # gatekeeper resurrect. This part of the logic will be refined.
        else:
            bucket = "generic"
            entry = process_generic(entry, command_plan) # use the generic handler process_generic helper function
            resurrected_total += 1
            resurrection_registry[uuid] = entry

        by_bucket.setdefault(bucket, {
            "resurrection_candidates": 0,
            "ghost_candidates": 0,
            "selected_for_resurrection": 0
        })

        # Candidate gating
        if status in ("install_failed", "stub"):
            by_bucket[bucket]["resurrection_candidates"] += 1
        elif status == "ghost":
            by_bucket[bucket]["ghost_candidates"] += 1

        if bucket in ("idx1", "generic", "ghost"):
            by_bucket[bucket]["selected_for_resurrection"] += 1



    #stats_out = {
    #    "total_candidates_gatekeeper": len(resurrection_registry),
    #    "selected_for_resurrection_total": resurrected_total,
    #    "by_bucket_counts": by_bucket,
    #    "selected_for_resurrection_rate_overall": (
    #        (resurrected_total / max(1, len(resurrection_registry))) * 100.0
    #    ),
    #    "timestamp": datetime.utcnow().isoformat()
    #}

    stats_out = {
        "total_resurrection_candidates": sum(
            bucket["resurrection_candidates"] for bucket in by_bucket.values()
        ),
        "total_ghost_candidates": sum(
            bucket["ghost_candidates"] for bucket in by_bucket.values()
        ),
        "selected_for_resurrection_total": resurrected_total,
        "by_bucket_counts": by_bucket,
        "selected_for_resurrection_rate_overall": (
            (resurrected_total / max(
                1,
                sum(bucket["resurrection_candidates"] for bucket in by_bucket.values())
                + sum(bucket["ghost_candidates"] for bucket in by_bucket.values())
            )) * 100.0
        ),
        "timestamp": datetime.utcnow().isoformat()
    }


    # registry output stays in base logs
    write_json("resurrection_module2e_registry.json", resurrection_registry, log_dir=LOG_DIR)
    
    # stats output goes into /aws_EC2/logs/statistics
    write_json("aggregate_selected_for_resurrection_stats_module2e.json", stats_out, log_dir=STATISTICS_DIR)



    ## Final summary printout
    #print(f"[module2e_logging] Summary: candidates={len(resurrection_registry)}, "
    #      f"selected_for_resurrection={resurrected_total}, "
    #      f"rate={stats_out['selected_for_resurrection_rate_overall']:.2f}%")
    #print(f"[module2e_logging] By bucket counts: {by_bucket}")

    # Final summary printout
    print(f"[module2e_logging] Summary: "
          f"total_resurrection_candidates={stats_out['total_resurrection_candidates']}, "
          f"total_ghost_candidates={stats_out['total_ghost_candidates']}, "
          f"selected_for_resurrection={stats_out['selected_for_resurrection_total']}, "
          f"rate={stats_out['selected_for_resurrection_rate_overall']:.2f}%")
    print(f"[module2e_logging] By bucket counts: {by_bucket}")


if __name__ == "__main__":
    main()

