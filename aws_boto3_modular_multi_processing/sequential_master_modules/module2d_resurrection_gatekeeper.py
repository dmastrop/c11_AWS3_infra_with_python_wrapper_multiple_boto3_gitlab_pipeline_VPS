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

        synthetic_uuid = f"ghost_{ip.replace('.', '_')}"
        synthetic_entry = {
            "status": "ghost",
            "attempt": -1,
            "pid": None,
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
