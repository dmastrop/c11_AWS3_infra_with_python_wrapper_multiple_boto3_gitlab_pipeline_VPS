##### Test case
#
#def main():
#    log_path = "/aws_EC2/logs/gitlab_full_run.log"
#    match_phrase = "install_success"
#
#    print(f"[TRACE][module2b] Starting ghost log scan for phrase: '{match_phrase}'")
#
#    try:
#        with open(log_path, "r") as f:
#            match_count = 0
#            for line in f:
#                if match_phrase in line:
#                    print(f"[MATCH] {line.strip()}")
#                    match_count += 1
#        print(f"[TRACE][module2b] Total matches found: {match_count}")
#    except FileNotFoundError:
#        print(f"[ERROR][module2b] Log file not found: {log_path}")




#### Post ghost analysis with json file schema 
#- Streams the console log line-by-line (no buffering)
#- Tags ghosts based on absence of expected signals
#-  Detects SSH attempts using `"Attempting to connect to"`
#-  Extracts `process_index` from chunk assignment lines  (NOTE: process_index is not the same as the PID)
#-  Avoids false tagging of stubs by relying on ghost IPs only, otherwise some stubs could be aggregated into this ghost detail json
#-  Includes full error handling and final JSON writeout



import json
import boto3

## This helper function is to add the private_ip address to the synthetic ghost registry_entry that is created in module2d
## If we inject it early on in module2b it can be queried from the aggregate_ghost_detail.json listing of ghosts that is 
## created in this module2b
def lookup_private_ip(public_ip, region=None):
    """
    Resolve the private IP for a given public IP using AWS EC2 describe_instances.
    Returns 'unknown' if not found.
    """
    try:
        session = boto3.Session(region_name=region or os.getenv("region_name"))
        ec2 = session.client("ec2")
        resp = ec2.describe_instances(Filters=[{"Name": "ip-address", "Values": [public_ip]}])
        for r in resp.get("Reservations", []):
            for i in r.get("Instances", []):
                return i.get("PrivateIpAddress", "unknown")
    except Exception as e:
        print(f"[WARN] lookup_private_ip failed for {public_ip}: {e}")
    return "unknown"





def main():
    ghost_summary_path = "/aws_EC2/logs/aggregate_ghost_summary.log"
    console_log_path = "/aws_EC2/logs/gitlab_full_run.log"
    output_path = "/aws_EC2/logs/aggregate_ghost_detail.json"

    ghost_entries = []
    ghost_ips = set()

    # Step 1: Parse ghost IPs from ghost summary
    try:
        
        with open(ghost_summary_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                for part in parts:
                    if part.count('.') == 3:
                        ghost_ips.add(part)


    except FileNotFoundError:
        print(f"[ERROR] Ghost summary file not found: {ghost_summary_path}")
        return

    print(f"[TRACE] Found {len(ghost_ips)} ghost IPs")

    


    # Step 2: Stream console log and tag each ghost IP
    try:
        for ip in ghost_ips:
            match_count = 0
            ssh_attempted = False
            process_index = None
            pid = None

            with open(console_log_path, "r") as f:
                for line in f:
                    if ip in line:
                        match_count += 1

                        if "Attempting to connect to" in line:
                            ssh_attempted = True

                        if "[DEBUG] Process" in line and "IPs =" in line:
                            try:
                                process_index = int(line.split("Process")[1].split(":")[0].strip())
                            except:
                                pass
                        
                        if f"👻 Ghost detected in process" in line and ip in line:
                            try:
                                pid = int(line.split("process")[1].split(":")[0].strip())
                            except:
                                pass



            tags = ["ghost"]
            
            if ssh_attempted:
                tags.append("ssh_attempted")
            else:
                tags.append("no_ssh_attempt")

            if match_count <= 2:
                tags.append("aws_outage_context")

            ghost_entries.append({
                "ip": ip,
                "private_ip": lookup_private_ip(ip),   # add the private_ip address to the module2b listing of ghost entries. Use 
                # the helper function lookup_private_ip based upon the public_ip ip.
                "pid": pid,
                "process_index": process_index,
                "tags": tags
            })

    except FileNotFoundError:
        print(f"[ERROR] Console log file not found: {console_log_path}")
        return

    


    # Step 3: Write to aggregate_ghost_detail.json
    with open(output_path, "w") as f:
        json.dump(ghost_entries, f, indent=2)

    print(f"[TRACE] Ghost detail written to: {output_path}")




# for master file indirection:
if __name__ == "__main__":
    main()

