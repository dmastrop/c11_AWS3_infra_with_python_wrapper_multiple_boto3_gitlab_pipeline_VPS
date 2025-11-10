import json
import os

def resurrection_gatekeeper_v4(registry_entry):
    status = registry_entry.get("status", "")
    tags = registry_entry.get("tags", [])
    resurrection_attempts = registry_entry.get("resurrect_count", 0)

    if status == "install_success":
        return False, "Install succeeded"

    ##### Make sure this block is BEFORE the install_failed/stub block below, otherwise this logic will never execute and that special
    ##### case below will never get hit.
    if "future_exception" in tags:
        if "install_success_achieved_before_crash" in tags:
            return False, "Crash occurred post-install: resurrection not needed"
        return True, "Tagged with future_exception"
    

    if status in {"install_failed", "stub"}:
        return True, f"Status = {status}"
    
    # add this ghost block for the process_ghost_registry function ghost processing. The status will be "ghost" and resurrection will 
    # always be attempted for these types of threads
    if status == "ghost":
        return True, "Ghost entry: resurrection always attempted"


    if resurrection_attempts >= 3:
        return False, "Resurrection attempts exceeded"

    return False, "No resurrection criteria met"

#### This function is to handle the special processing of the aggregate_ghost_detail.json. It requires transformation into standarized
#### registry_entry format. Once that is done teh resurrection_gatekeeper function is applied to those threads.  Note that these 
#### threads have a status ghost so that the resurrection_gatekeeper logic can be properly applied to them (see resurrection_gatekeeper
#### function above).  Note that pid is None but will be assigned in Phase3 once the thread requeing for resurrection is done.
#### Note that the thread_uuid is synthetic.   Note that the process_index is assigned even to missing ips (ghosts) very early during
#### the AWS control plane phase. Not sure yet if this can be correlated to an exising pid from the multiprocessor in Phase3. 
#### If not a new pid will have to be created in Phase3.

#### The log tags module2d.2a and module2d.2b are:
#| Step | Purpose | Output File |
#|------|--------|-------------|
#| **module2d.2a** | Convert ghost entries to synthetic registry format | `SYNTHETIC_OUTPUT_PATH = /aws_EC2/logs/aggregate_ghost_detail_synthetic_registry.json` |
#| **module2d.2b** | Apply resurrection gatekeeper logic to synthetic registry | `FINAL_OUTPUT_PATH = /aws_EC2/logs/aggregate_ghost_detail_module2d.json` |


def process_ghost_registry():
    INPUT_PATH = "/aws_EC2/logs/aggregate_ghost_detail.json"
    SYNTHETIC_OUTPUT_PATH = "/aws_EC2/logs/aggregate_ghost_detail_synthetic_registry.json"
    FINAL_OUTPUT_PATH = "/aws_EC2/logs/aggregate_ghost_detail_module2d.json"

    try:
        with open(INPUT_PATH, "r") as f:
            ghost_entries = json.load(f)
        print(f"[module2d.2a] Loaded ghost entries from: {INPUT_PATH}")
    except FileNotFoundError:
        print(f"[module2d.2a] ERROR: Ghost file not found.")
        return

    synthetic_registry = {}

    # Step 2a: Convert to synthetic registry format
    for ghost_entry in ghost_entries:
        ip = ghost_entry.get("ip")
        process_index = ghost_entry.get("process_index")
        tags = ghost_entry.get("tags", [])
        pid = ghost_entry.get("pid") # get the pid from the ghost_entry that is from module2b
        

        synthetic_uuid = f"ghost_{ip.replace('.', '_')}"
        synthetic_entry = {
            "status": "ghost",
            "attempt": -1,
            "pid": pid, # get the pid from the ghost_entry that is from module2b
            "thread_id": None,
            "thread_uuid": synthetic_uuid,
            "public_ip": ip,
            "private_ip": "unknown",
            "timestamp": None,
            "tags": tags,
            "process_index": process_index
        }

        synthetic_registry[synthetic_uuid] = synthetic_entry

    with open(SYNTHETIC_OUTPUT_PATH, "w") as f:
        json.dump(synthetic_registry, f, indent=2)
    print(f"[module2d.2a] Synthetic ghost registry written to: {SYNTHETIC_OUTPUT_PATH}")
    print(f"[module2d.2a] Total entries synthesized: {len(synthetic_registry)}")

    # Step 2b: Apply resurrection gatekeeper logic
    resurrected = []
    blocked = []

    for thread_uuid, registry_entry in synthetic_registry.items():
        decision, reason = resurrection_gatekeeper_v4(registry_entry)
        registry_entry["resurrection_reason"] = reason
        registry_entry.setdefault("tags", []).append(
            "gatekeeper_resurrect" if decision else "gatekeeper_blocked"
        )

        if decision:
            resurrected.append(thread_uuid)
            print(f"[module2d.2b] ✅ Resurrecting ghost UUID {thread_uuid} — Reason: {reason}")
        else:
            blocked.append(thread_uuid)
            print(f"[module2d.2b] ⛔ Blocking ghost UUID {thread_uuid} — Reason: {reason}")

    with open(FINAL_OUTPUT_PATH, "w") as f:
        json.dump(synthetic_registry, f, indent=2)
    print(f"[module2d.2b] Final ghost registry written to: {FINAL_OUTPUT_PATH}")
    print(f"[module2d.2b] Total resurrected: {len(resurrected)}")
    print(f"[module2d.2b] Total blocked: {len(blocked)}")



#### This function is to merge the 2 files that have been processed by the resurrection_gatekeeper and tagged accordingly.
#### The function combines the following json log files:
#| Source File | Description |
#|-------------|-------------|
#| `final_aggregate_execution_run_registry_module2d.json` | Threads from module2c, tagged by gatekeeper |
#| `aggregate_ghost_detail_module2d.json` | Ghost threads, transformed and tagged by gatekeeper |
#### The merged file is called resurrection_gatekeeper_final_registry_module2d.json
#### These logs are tagged with [module2d.3] in the gitlab console logs.


def merge_resurrection_registries():
    REGISTRY_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry_module2d.json"
    GHOST_PATH = "/aws_EC2/logs/aggregate_ghost_detail_module2d.json"
    MERGED_OUTPUT_PATH = "/aws_EC2/logs/resurrection_gatekeeper_final_registry_module2d.json"

    try:
        with open(REGISTRY_PATH, "r") as f:
            registry_entries = json.load(f)
        print(f"[module2d.3] Loaded registry entries from: {REGISTRY_PATH}")
    except FileNotFoundError:
        print(f"[module2d.3] ERROR: Registry file not found.")
        registry_entries = {}

    try:
        with open(GHOST_PATH, "r") as f:
            ghost_entries = json.load(f)
        print(f"[module2d.3] Loaded ghost entries from: {GHOST_PATH}")
    except FileNotFoundError:
        print(f"[module2d.3] ERROR: Ghost file not found.")
        ghost_entries = {}

    # Merge both dictionaries
    merged_registry = {**registry_entries, **ghost_entries}

    with open(MERGED_OUTPUT_PATH, "w") as f:
        json.dump(merged_registry, f, indent=2)
    print(f"[module2d.3] Final merged registry written to: {MERGED_OUTPUT_PATH}")
    print(f"[module2d.3] Total entries in final registry: {len(merged_registry)}")


#### This function is to compile the gatekeeper stats.   This file uses the merged process threads + ghosts gatekeeper processed
#### file: resurrection_gatekeeper_final_registry_module2d.json AND the aggregate_process_stats.json file from module2's main(),
#### and appends the resurrection gatekeeper stats to the aggregate_process__stats.json file.  The final filename is called
#### aggregate_process_stats_gatekeeper_module2d.json")
#### This function executes after the main() code and after all of the above functions
def aggregate_gatekeeper_stats():
    import os
    import json

    STATS_DIR = "/aws_EC2/logs/statistics"
    FINAL_REGISTRY_PATH = "/aws_EC2/logs/resurrection_gatekeeper_final_registry_module2d.json"
    AGGREGATE_STATS_PATH = os.path.join(STATS_DIR, "aggregate_process_stats.json")
    OUTPUT_PATH = os.path.join(STATS_DIR, "aggregate_process_stats_gatekeeper_module2d.json")

    try:
        with open(FINAL_REGISTRY_PATH, "r") as f:
            final_registry = json.load(f)
        print(f"[module2d.4] Loaded final registry from: {FINAL_REGISTRY_PATH}")
    except FileNotFoundError:
        print(f"[module2d.4] ERROR: Final registry file not found.")
        return

    try:
        with open(AGGREGATE_STATS_PATH, "r") as f:
            aggregate_stats = json.load(f)
        print(f"[module2d.4] Loaded aggregate stats from: {AGGREGATE_STATS_PATH}")
    except FileNotFoundError:
        print(f"[module2d.4] ERROR: Aggregate stats file not found.")
        return

    # Count gatekeeper decisions
    resurrected = 0
    blocked = 0

    for entry in final_registry.values():
        tags = entry.get("tags", [])
        if "gatekeeper_resurrect" in tags:
            resurrected += 1
        elif "gatekeeper_blocked" in tags:
            blocked += 1

    # Resurrection rate = resurrected / (resurrection candidates + ghost candidates)
    total_res_candidates = aggregate_stats.get("total_resurrection_candidates", 0)
    total_ghost_candidates = aggregate_stats.get("total_resurrection_ghost_candidates", 0)
    resurrection_denominator = total_res_candidates + total_ghost_candidates
    resurrection_rate = (
        (resurrected / resurrection_denominator) * 100 if resurrection_denominator > 0 else 0.0
    )

    # Gatekeeper rate = resurrected / (total threads + ghost IPs)
    total_threads = aggregate_stats.get("total_threads", 0)
    ghost_ips = aggregate_stats.get("unique_missing_ips_ghosts", [])
    gatekeeper_denominator = total_threads + len(ghost_ips)
    gatekeeper_rate = (
        (resurrected / gatekeeper_denominator) * 100 if gatekeeper_denominator > 0 else 0.0
    )

    # Append gatekeeper stats
    aggregate_stats["gatekeeper_resurrected"] = resurrected
    aggregate_stats["gatekeeper_blocked"] = blocked
    aggregate_stats["gatekeeper_total"] = resurrected + blocked
    aggregate_stats["gatekeeper_resurrection_rate_percent"] = round(resurrection_rate, 2)
    aggregate_stats["gatekeeper_rate_percent"] = round(gatekeeper_rate, 2)

    with open(OUTPUT_PATH, "w") as f:
        json.dump(aggregate_stats, f, indent=2)

    print(f"[module2d.4] Gatekeeper stats appended and written to: {OUTPUT_PATH}")
    print(f"[module2d.4] ✅ Resurrection rate = resurrected / (resurrection candidates + ghost candidates)")
    print(f"[module2d.4] ✅ Gatekeeper rate = resurrected / (total threads + ghost IPs)")
    print(f"[module2d.4] Resurrected: {resurrected}, Blocked: {blocked}, Total: {resurrected + blocked}")
    print(f"[module2d.4] Resurrection Rate: {resurrection_rate:.2f}%")
    print(f"[module2d.4] Gatekeeper Rate: {gatekeeper_rate:.2f}%")




def main():
    REGISTRY_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry_module2c.json"
    FALLBACK_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry.json"
    OUTPUT_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry_module2d.json"

    # Load registry with fallback
    try:
        with open(REGISTRY_PATH, "r") as f:
            registry = json.load(f)
        print(f"[module2d.1] Loaded registry from: {REGISTRY_PATH}")
    except FileNotFoundError:
        try:
            with open(FALLBACK_PATH, "r") as f:
                registry = json.load(f)
            print(f"[module2d.1] WARNING: Fallback to original registry: {FALLBACK_PATH}")
        except FileNotFoundError:
            print(f"[module2d.1] ERROR: Neither registry file found.")
            return

    resurrected = []
    blocked = []

    for thread_uuid, registry_entry in registry.items():
        ip = registry_entry.get("public_ip")

        # Defensive check: ghost_entry will almost always be None here,
        # since ghost IPs are not present in the registry. Included only
        # to catch rare edge cases where a ghost IP was partially hydrated.
        ghost_entry = None

        decision, reason = resurrection_gatekeeper_v4(registry_entry)

        if decision:
            registry_entry.setdefault("tags", []).append("gatekeeper_resurrect")
            registry_entry["resurrection_reason"] = reason
            resurrected.append(thread_uuid)
            print(f"[module2d.1] ✅ Resurrecting UUID {thread_uuid} (IP: {ip}) — Reason: {reason}")
        else:
            registry_entry.setdefault("tags", []).append("gatekeeper_blocked")
            registry_entry["resurrection_reason"] = reason
            blocked.append(thread_uuid)
            print(f"[module2d.1] ⛔ Blocking UUID {thread_uuid} (IP: {ip}) — Reason: {reason}")

    # Write output even if no resurrection candidates found
    with open(OUTPUT_PATH, "w") as f:
        json.dump(registry, f, indent=2)

    print(f"[module2d.1] Registry resurrection complete.")
    print(f"[module2d.1] Total resurrected: {len(resurrected)}")
    print(f"[module2d.1] Total blocked: {len(blocked)}")
    print(f"[module2d.1] Output written to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

    process_ghost_registry()  # the process_ghost_registry requires special code to transform the original and then apply resurrection
    # gatekeeper. See the function above. This is called after the module2d.1 processing.  The ghost processing is module2d.2a and 
    # module2d.2b in the logs.

    merge_resurrection_registries()  # this function merges the ghost registry and aggregate registry that has been processed by
    # the resurrection_gatekeeper into one file so that the Phase3 resurrection code can consume it and reque the threads 
    # accordingly.

    aggregate_gatekeeper_stats()  # this function has inputs of the module2 main() aggregate stats json file and  the 
    # final_aggregate_execution_run_registry_module2d.json that has all the gateway decisions (in the tags of the regisry_entrys
    # This function has to run at the very end of this module2d.
