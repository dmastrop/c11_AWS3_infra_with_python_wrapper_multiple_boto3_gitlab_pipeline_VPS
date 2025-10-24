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

import json

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
                if "ghost" in line.lower():
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

            tags = ["ghost"]
            if ssh_attempted:
                tags.append("ssh_attempted")
            else:
                tags.append("no_ssh_attempt")

            if match_count <= 2:
                tags.append("aws_outage_context")

            ghost_entries.append({
                "ip": ip,
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

