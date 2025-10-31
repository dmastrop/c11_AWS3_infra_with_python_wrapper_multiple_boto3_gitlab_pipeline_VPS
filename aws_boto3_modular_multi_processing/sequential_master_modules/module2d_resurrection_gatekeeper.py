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
            return False, "Crash occurred post-install — resurrection not needed"
        return True, "Tagged with future_exception"
    

    if status in {"install_failed", "stub"}:
        return True, f"Status = {status}"


    if resurrection_attempts >= 3:
        return False, "Resurrection attempts exceeded"

    return False, "No resurrection criteria met"

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

