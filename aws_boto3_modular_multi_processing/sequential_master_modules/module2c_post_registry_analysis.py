import json

def main():
    REGISTRY_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry.json"
    CONSOLE_LOG_PATH = "/aws_EC2/logs/gitlab_full_run.log"
    OUTPUT_PATH = "/aws_EC2/logs/final_aggregate_execution_run_registry_module2c.json"




    # Step 1: Load registry
    try:
        with open(REGISTRY_PATH, "r") as f:
            registry = json.load(f)
    except FileNotFoundError:
        print(f"[module2c] ERROR: Registry file not found: {REGISTRY_PATH}")
        return



    # Step 2: Extract candidate IPs
    ####  `candidate_ips`
    #It’s a dictionary mapping `thread_uuid → public_ip`
    #These are registry entries that match all three tags:
    #  - `"install_failed"`
    #  - `"future_exception"`
    #  - `"ip_rehydrated"`


    candidate_ips = {
        uuid: entry["public_ip"]
        for uuid, entry in registry.items()
        if all(tag in entry.get("tags", []) for tag in ["install_failed", "future_exception", "ip_rehydrated"])
    }

    print(f"[module2c] Found {len(candidate_ips)} candidate registry entries")




    # Step 3: Scan console log for installation success
    #`matched_installation_succeeded_ips` (renamed from `successful_ips`)]
    #It’s a set of IPs parsed from the GitLab console log line:Installation succeeded on the following IPs: ...
    #These are IPs that successfully completed installation before crashing


    matched_installation_succeeded_ips = set()

    try:
        with open(CONSOLE_LOG_PATH, "r") as f:
            for line in f:
                if "Installation succeeded on the following IPs:" in line:
                    for ip in line.strip().split(":")[1].split(","):
                        ip = ip.strip()
                        if ip:
                            matched_installation_succeeded_ips.add(ip)
    except FileNotFoundError:
        print(f"[module2c] ERROR: Console log file not found: {CONSOLE_LOG_PATH}")
        return

    print(f"[module2c] Found {len(matched_installation_succeeded_ips)} IPs with successful installation in console log")




    # Step 4: Tag matching registry entries
    modified_count = 0
    for uuid, ip in candidate_ips.items():
        if ip in matched_installation_succeeded_ips:
            registry[uuid]["tags"].append("install_success_achieved_before_crash")
            print(f"[module2c] Tagged UUID {uuid} (IP: {ip}) with 'install_success_achieved_before_crash'")
            modified_count += 1

    print(f"[module2c] Total registry entries tagged: {modified_count}")






    # Step 5: Write updated registry (make sure this is created even if no changes,  to be consistent with other aggregate logs)
    ### 3. Registry Modification
    #The `registry` object is the full original registry loaded from `final_aggregate_execution_run_registry.json`
    #The code modifies only the entries that match the criteria and IPs
    #The output file (`final_aggregate_execution_run_registry_module2c.json`) contains the **entire registry**, with the modified entries tagged
    #If multiple entries qualify, all will be tagged accordingly

    with open(OUTPUT_PATH, "w") as f:
        json.dump(registry, f, indent=2)

    if modified_count == 0:
        print(f"[module2c] No registry entries qualified for tagging. Output file still written for consistency.")
    else:
        print(f"[module2c] Updated registry written to: {OUTPUT_PATH}")





# Entry point
if __name__ == "__main__":
    main()

