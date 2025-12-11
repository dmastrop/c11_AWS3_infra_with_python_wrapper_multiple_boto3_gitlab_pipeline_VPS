import json
import os
from datetime import datetime
import boto3

## Version 2 of module2e
## Import of futures for the use of the ThreadPoolExecutor in the post execution block after main() (see below). 
from concurrent.futures import ThreadPoolExecutor, as_completed



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







# --- TEST OVERRIDE: inject fake InstanceId for ghosts ---
# This will test the instance_id present reboot and health check code added to the process_ghost handler in module2e
# It is also used to test the no_instance_id logic in module2f
# It needs to be included in both modules to provide instance_id consistency between the two modules as far as the testing is concerned.
# There are two variants that are tested. One has an invalid instance_id format
# The other is a valid instance_id format
#resolve_instance_id = lambda **kwargs: "i-FAKE1234567890TEST"  ## invalid instance_id format. This will invoke Malformed from the AWS API
#resolve_instance_id = lambda **kwargs: "i-033f7957281756224"   ## Valid instance_id format. This will invole InvalidInstanceID.NotFound from the AWS API


# --- TEST OVERRIDE: inject fake InstanceId for ghosts ---
# Controlled by ENV variable in gitlab-ci.yml
# Set INJECT_FAKE_INSTANCE_ID=true to activate
# Set the FAKE_INSTANCE_ID in gitlab-ci.yml.  For example, i-033f7957281756224
# Note that the FACKE_INSTANCE_ID format has to be "correct". Best to use a recently retired node instance_id. These are AWS cached after a while and
# need to be refreshed with a more recent one periodically.
  # For example, i-1234567890abcdef0 looks to be correct format but AWS API will return InvalidInstanceID.Malformed
  # The i-033f7957281756224 is a recently retired node real instance_id and this worked prior to AWS caching it as no longer valid.
  # While it worked it behaved in the code as a real instance_id (during reboot loop the watchdog had to timeout eventually since it is no longer atached
  # to a node).  When it stopped working after AWS caching, AWS API flagged it as InvalidInstanceID.NotFound and this tests a different part of the python
  # code.
if os.getenv("INJECT_FAKE_INSTANCE_ID", "false").lower() in ("1", "true", "yes"):
    fake_id = os.getenv("FAKE_INSTANCE_ID", "i-FAKE1234567890TEST")
    resolve_instance_id = lambda **kwargs: fake_id
    print(f"[TEST] Overriding resolve_instance_id → {fake_id}")






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

    
    ##### Version 2 of module2e.py
    ##### Remove the calls to reboot_instance and health_check_instance from the ghost process handler process_ghost 
    ##### This is for the refactoriing to make the reboot code multi-threading. Need to decouple the reboot code from the handler codes so that any
    ##### handler can utlize the reboot code if need be. The multi-treading reboot code will be appended to the main() function below (see below) and executed
    # Add the calls to reboot_instance and health_check_instance for instance_id present case. The else ensures that instance_id will be present. Note for the 
    # instance_id present case the tag will be pre_resurrection_reboot_required: True
   
    #else:
    #    # Real ghost → attempt reboot + health check
    #    reboot_ok = reboot_instance(instance_id, region=region)
    #    if not reboot_ok:
    #        log_ghost_context(entry, "reboot_failed")
    #        entry["status"] = "install_failed"
    #        return entry

    #    health_ok = health_check_instance(instance_id, region=region)
    #    if not health_ok:
    #        log_ghost_context(entry, "health_checks_not_ok")
    #        entry["status"] = "install_failed"
    #        return entry

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
    # Note that the iteration through the registy is serial but if a reboot is required that is done as post processing after main() (see below) and is 
    # batch processed (multi-threaded). Basically any module2e registry with pre_resurrection_reboot_required wil be post processsed rebooted as a batch.
    # This decouples the reboot process from the handler process (i.e. process_ghost for example)
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


#### end of main() #####


#### Version 2 of module2e #####
#================ post processing functions for rebooting  (module2e2) ===========

LOG_DIR = "/aws_EC2/logs"
IN_PATH = os.path.join(LOG_DIR, "resurrection_module2e_registry.json")
OUT_PATH = os.path.join(LOG_DIR, "resurrection_module2e_registry_rebooted.json")




def load_registry(path=IN_PATH):
    if not os.path.exists(path):
        print(f"[module2e2] Missing registry at {path}")
        return {}
    with open(path, "r") as f:
        return json.load(f)




def save_registry(reg, path=OUT_PATH):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump(reg, f, indent=2)
    print(f"[module2e2] Wrote reboot-annotated registry to {path}")




## This sets the reboot_context tags in the registry_entry

def mark(entry, tag):
    entry.setdefault("tags", []).append(f"reboot_context:{tag}")




## note that reboot_instance and health_check_instance are the original unchanged functions in utils.py
## Thus the validation will provide very similar  gitlab console logs when compared to the serialized case
## The mark function is used to set teh reboot_context tag in each of the various reboot scenarios. 
## As noted below the registry_entrys that have gone through attempted reboot will ALWAYS be passed on to module2f for an actualy attempted resurrection.
## Module2f will then empirically set the final status in these threads/registry_entrys.   The status should never be set by this module2e.

def reboot_and_check(uuid, entry, region=None, max_wait=300, poll_interval=15):
    iid = entry.get("instance_id")
    if not iid:
        mark(entry, "no_instance_id_skip")
        return uuid, entry

    mark(entry, "initiated")
    ok = reboot_instance(iid, region=region, max_wait=max_wait, poll_interval=poll_interval)
    if not ok:
        mark(entry, "reboot_failed")
        # optional: entry["status"] = "install_failed"
        return uuid, entry

    ok2 = health_check_instance(iid, region=region)
    if not ok2:
        mark(entry, "health_checks_not_ok")
        # optional: entry["status"] = "install_failed"
        return uuid, entry

    mark(entry, "ready")
    return uuid, entry





def batch_reboot_registry(region=None, max_workers=16):
    reg = load_registry()
    if not reg:
        return

    # Select reboot targets
    targets = {uuid: e for uuid, e in reg.items() if e.get("pre_resurrection_reboot_required") is True}
    print(f"[module2e2] Reboot targets: {len(targets)}")

    ## The futures call the reboot_and_check function (in parallel) which calls the original reboot_instance and health_check_instance that was
    ## used in the serialized case.  The futures call the subset pre_resurrection_reboot_required registry_entrys  (targets) from the original module2e registry. Only a subset of the module2e registry nodes need to be rebooted

    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(reboot_and_check, uuid, entry, region): uuid for uuid, entry in targets.items()}
        for fut in as_completed(futs):
            uuid, updated = fut.result()
            updated["timestamp_reboot_stage"] = datetime.utcnow().isoformat() + "Z"
            results[uuid] = updated

    # Merge results back into registry (updated reg). This registry is the same list of registry_entrys from the  original module2e
    # but they are now tagged with the reboot_context tags if they have the pre_resurrection_reboot_required
    for uuid, updated in results.items():
        reg[uuid] = updated

    # Basic readiness gate (optional): ensure all reboot-required entries are ready or logged failed
    not_ready = [
        uuid for uuid, e in reg.items()
        if e.get("pre_resurrection_reboot_required") is True
        and "reboot_context:ready" not in (e.get("tags") or [])
        and "reboot_context:reboot_failed" not in (e.get("tags") or [])
        and "reboot_context:health_checks_not_ok" not in (e.get("tags") or [])
    ]
    if not_ready:
        print(f"[module2e2] Warning: {len(not_ready)} entries not ready post-reboot stage")

    save_registry(reg)
    
    ## note that reboot not_ready((just has reboot_context:initiated), reboot_context:ready and reboot_context:reboot_failed and reboot_context:
    ## health_checks_not_ok are still all included in the updated registry and the module2f will still try to resurrect all the registry_entrys
    ## Don't attempt to change the status in module2e. Module2f will update the registry_entry status after it tries to resurrect each of the
    ## problematic threads or ghost ips.
    ## The original module2e registry: resurrection_module2e_registry.json AND the updated module2e registry with post.
    ## reboot_context tags, should have the exact same number of registry_entrys in them.  All of them need to be resurrected by
    ## module2f (attempted). This part of module2e merely identifies those that need to be rebooted and then attempts a reboot
    ## and then tags them accordingly with the reboot_context tag.
    ## At minimum such registry_entrys will have the reboot_context: initiated (not_ready). If the reboot fails or succeeds (ready), etc
    ## the registry_entry will be updated as such with the appropriate reboot_context tag.



if __name__ == "__main__":
    main()
    # Version 2 of module2e
    # Post processing reboot function after main() for the multi-threaded version of the reboot code. This also decouples
    # the reboot code from the handler code (for example, process_ghost handler).
    # region could be pulled from env
    batch_reboot_registry(region=os.getenv("region_name"))



