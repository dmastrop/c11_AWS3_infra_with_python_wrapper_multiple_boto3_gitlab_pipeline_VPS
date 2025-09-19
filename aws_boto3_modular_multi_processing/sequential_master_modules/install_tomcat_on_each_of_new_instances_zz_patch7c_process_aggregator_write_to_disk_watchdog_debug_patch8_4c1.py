
# This version has further optimizations to the install tomcat code. Since there are so many instances, this
# needs to utilize not only the current ThreadPoolExecutor but also wrap the current install_tomcat_on_instances
# function with main that does the following:
# Still use the ThreadPoolExecutor but:
# The script now uses multi-processing to distribute the SSH connections across multiple cores. Each process handles a chunk of instances.
# Continue to use (call) the ThreadPoolExecutor Within each process, the `ThreadPoolExecutor` is used to run installations in parallel, matching the number of CPU cores available.  There are 6 CPU cores on the VPS. So each core will be running
# the ThreadPoolExecutor with a group of installations on each core.
# NOTE that Archlinux suppports multi-processing.



# Move the imports to outside of the functions. This is ok as all functions in this file will now have access to the 
# imported dependencies.

import multiprocessing
import threading
import logging
import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
import uuid
import random
import string
import botocore.exceptions
import time
import psutil
from contextlib import contextmanager
from io import StringIO
from datetime import datetime
import psutil
import re # this is absolutely required for all the stuff we are doing in the resurrection_monitor functino below!!!!!!
import math # for math.ceil watchdog timeout adaptive code




## This is the whitelist code to be used in install_tomcat for categorizing the status of the registry_entry of the
## threads.  The helper function is used in install_tomcat to do a pattern search for this whitelist in the STDERR
## output flush from read_output_with_watchdog that is called from install_tomcat
## The list is dynamic and other command taxonomy (like yum, etc) will be added to make this agnostic to the actual
## commands.


APT_WHITELIST_REGEX = [
    r"Reading state information.*",
    r"Run 'apt list --upgradable' to see them.*",
    r"WARNING: apt does not have a stable CLI interface.*",
    r"Reading package lists.*",
    r"Building dependency tree.*",
    r"Preparing to unpack.*",
    r"Unpacking.*",
    r"Setting up.*",
    r"Processing triggers for.*",
    r"update-alternatives:.*",
    r"Get:.*",
    r"Hit:.*",
    r"Fetched .* in .*",
    r"Reading database .*",
    r"Selecting previously unselected package .*",
    r"0 upgraded, .* not upgraded",
    r"Waiting for cache lock: Could not get lock .*lock-frontend.*", #added
    r"debconf: delaying package configuration.*",  #Deferred config during apt install
    r"update-initramfs:.*",  #Kernel/initramfs update messages         
    r"systemd-sysv-generator.*", #Systemd compatibility notices            
    r"invoke-rc.d:.*",  #Init script invocation (non-fatal)       
    r"insserv: warning: script.*",  #Legacy init script warnings              
    r"insserv: warning: current start runlevel.*"  #Runlevel compatibility warning         
    r"\(Reading database \.\.\. \d+%.*",  # refining
    r"\(Reading database \.\.\. \d+ files and directories currently installed\.\)", # refining
    r".*\.deb \.\.\. .*",  # refining

    # Already installed confirmation
    r".* is already the newest version.*",

    # No changes summary
    r"0 upgraded, 0 newly installed, 0 to remove and .* not upgraded",

    # Package metadata fetch
    r"Reading package lists... Done",
    r"Building dependency tree... Done",
    r"Reading state information... Done",

    # Locale or language warnings (sometimes noisy but harmless)
    r"perl: warning: Setting locale failed.*",
    r"perl: warning: Falling back to the standard locale.*"

    r"The following additional packages will be installed:"
    r"Suggested packages:"
    r"The following NEW packages will be installed:"
    r"Need to get .* of archives\."
    r"After this operation, .* of additional disk space will be used\."
    r"\(Reading database \.\.\. *",  # catches incomplete progress lines

    # This next block was found by hitting the infamous exit_code = 0 but non_whitelisted_stderr BLOCK3 code block only found
    # by running the large node 512 test.
    r"\d+ packages can be upgraded\. Run 'apt list --upgradable' to see them\.",
    r"Building dependency tree\.\.\.",
    r"Reading state information\.\.\.",
    r"\(Reading database \.\.\. ?\d*%?\)?"


]


# adding whitelist for the strace that is used with bash or bash like command "commands" in the list (these are not failures)
# With this whitelist in place all the original error logic for APT will apply to discriminate between stub, install_failed
# and install_success status for the registry_entry

STRACE_WHITELIST_REGEX = [
    r"write\(2, .* = \d+\)",  # benign stderr writes
    r'write\(1, ".*\\n", \d+\) *= *\d+', # to catch the \n on positive writes; escaped newline version
    r'write\(1, .*\\n.* = \d+\)',  # to catch the \n on positive writes; fallback catch-all


    r"execve\(.*\) = 0",      # successful exec calls
    r"\+\+\+ exited with 0 \+\+\+",  # clean exit

    # Benign stdout writes (e.g., echoing script content)
    r"write\(1, .* = \d+\)",

    # Successful sudo exec
    r"execve\(\"/usr/bin/sudo\", .* = 0",

    # SIGCHLD noise from child process exits
    r"--- SIGCHLD .* ---",

    # To catch common subprocesses used in injected commands. We want to whitelist these in the injected stderr as not failures
    r"execve\(\"/usr/bin/bash\", .* = 0",
    r"execve\(\"/usr/bin/python3\", .* = 0",

]




WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX  # + YUM_WHITELIST_REGEX, etc.

def is_whitelisted_line(line):
    return any(re.match(pattern, line) for pattern in WHITELIST_REGEX)

#def is_whitelisted_line(line):
#    return any(re.match(pattern, line) for pattern in APT_WHITELIST_REGEX)


### Will make this helper function extensible in the future:
#def is_whitelisted_line(line, tool="apt"):
#      regex_map = {
#          "apt": APT_WHITELIST_REGEX,
#          "yum": YUM_WHITELIST_REGEX,
#          ...
#      }
#      return any(re.match(pattern, line) for pattern in regex_map.get(tool, []))









## These are the status tags that can be used with the registry_entry. This list is dynamic and will be modified as 
## failure and stub code is added

STATUS_TAGS = {
    "install_success",
    "install_failed",
    "stub",
    "gatekeeper_resurrect",
    "watchdog_timeout",
    "ssh_initiated_failed",
    "ssh_retry_failed",
    "no_tags"
}



## These variables are used throughout for the resurrection based code. Put at top of module for easy reference
# :=:= Module-level constants for resurrection/watchdog logic
WATCHDOG_TIMEOUT          = 90   # seconds before we declare a read stalled. This is the default. The WATCHDOG_TIMTOUE is now
# adaptive. See the function get_watchdog_timeout. 
RETRY_LIMIT               = 3    # number of re-executes per SSH command (for example install tomcat9)
SLEEP_BETWEEN_ATTEMPTS    = 5    # seconds to wait between retries
STALL_RETRY_THRESHOLD     = 1    # number of watchdog reattempts for each command in the for attempt loop. Note that this has
# nothing to do with the command attempt number. That is the number attempts in attempting to execute the command on the node.


# global vars used for the modified retry_with_backoff() function as part of the adaptive watchdog timeout.
# Will continue to use the global var WATCHDOG_TIMEOUT above, but it will be overwritten per process
# This is ok as per process memory is segregated
# Per-process tracker for the highest retry attempt seen
max_retry_observed = 0  # default initialize it at 0

retry_lock = threading.Lock() 
# this prevents multiple threads from messing up the max_retry_observed that is calculated in the call to retry_with_backoff
# when there are multiple threads per process updating the max_retry_observed for each process.





## helper function used for the strace command syntax by the install_tomcat for idx commands/for attempt retry loop
## The strace code needs a trace.log file to hold its output prior to injecting it into stderr, and we need to 
## have unique trace.log filenames, and this appends a suffix to the trace_suffix.log filename. This prevents cross
## log corruption between command execution, retries of command execution at the per thread level. So 
## commands and retries all use unique trace.log filenames per thread.
def generate_trace_suffix():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))



## aggregate gold ips from chunks
## Global helper function for the GOLD standard IP list creation from the AWS control plane for the execution run
## This function will be called from main() after chunks is defined. Chunks is the pre-processsing done on the 
## complete AWS control list of IP addresses in the execution run. It needs to be processed to pull out the public ip
## addresses. This IP list will be used as  GOLD standard to compare the aggregated registry list to. Any missing ips
## are considered "true" ghosts (threads that have no registry value and thus no failure status tag by which to
## resurrect them). The only way to track these ghosts is through the IP address from the AWS control plane.
## gold_ips will be returned to the main() so that it can compare it to the aggregate registry list and create a
## log and json file as artifacts to gitlab pipeline

def hydrate_aggregate_chunk_gold_ip_list(chunks, log_dir):
    gold_ips = set()
    for chunk in chunks:
        for ip_info in chunk:
            ip = ip_info.get("PublicIpAddress")
            if ip:
                gold_ips.add(ip)

    output_path = os.path.join(log_dir, "aggregate_chunk_gold_ip_list.log")
    with open(output_path, "w") as f:
        for ip in sorted(gold_ips):
            f.write(ip + "\n")

    return gold_ips





## Global helper function for resurrection_monitor_patch7d. This 7d2  is the hydrate_benchmark_ips() helper function that
## replaces the exisiting working code in the resurrection monitor for creating the benchmark_ips_artifact.log file
## from the benchmark_combined_runtime.log which is from the process level pid logs. These are real time logs of the actual
## IP/threads that were created for each process (created during the control plane setup phase). This is used to created the 
# benchmark_ips,  the GOLD IP list used by main() to detect ghosts at the aggregate level. 
## benchmark_ips is used to then create the bencmarrk_ips_artifact.log list of total IPs (runtime) during the execution run
## and output as artifact to gitlab pipeline.
## The artifact creation is done in resurrection_monitor_patch7d after calling this function from the return benchmark_ips

# === RESMON PATCH7D UTILITY ===
### 🧩 `hydrate_benchmark_ips()` Function
def hydrate_benchmark_ips(log_dir):
    benchmark_combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
    benchmark_ips = set()

    try:
        with open(benchmark_combined_path, "r") as f:
            lines = f.readlines()
            print(f"[RESMON_7d] Runtime log line count: {len(lines)}")

            public_ip_lines = [line for line in lines if "Public IP:" in line]
            print(f"[RESMON_7d] Sample 'Public IP:' lines: {public_ip_lines[:3]}")

            for i, line in enumerate(lines):
                if "Public IP:" in line:
                    print(f"[RESMON_7d] Raw line {i}: {repr(line)}")
                    ip_matches = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                    if ip_matches:
                        print(f"[RESMON_7d] Matched IPs: {ip_matches}")
                    else:
                        print(f"[RESMON_7d] No IP match in line {i}: {line.strip()}")

            benchmark_ips = {
                match.group(1)
                for line in lines
                if (match := re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line))
            }
            print(f"[RESMON_7d] Hydrated benchmark IPs: {benchmark_ips}")

    except Exception as e:
        print(f"[RESMON_7d] Failed to hydrate benchmark IPs: {e}")

    return benchmark_ips



## Global helper function for resurrection_monitor_patch7d. This 7d2 is the detect_ghosts() helper function that
## replaces the new code in the resurrection monitor for ghost thread identification and logging. The function below
## will simply modularize that code so that res monitor can now call it cleanly.

# === RESMON PATCH7D UTILITY ===
### 🧩 `detect_ghosts()` Function
def detect_ghosts(process_registry, assigned_ips, pid, ts, log_dir):
    # Extract seen IPs from the current process registry
    seen_ips = {entry["public_ip"] for entry in process_registry.values() if entry.get("public_ip")}
    # Build assigned IPs set from the chunk passed to this process
    assigned_ip_set = {ip["PublicIpAddress"] for ip in assigned_ips}
    # Detect ghosts — IPs assigned to this process but missing from registry
    ghosts = sorted(assigned_ip_set - seen_ips)

    # Debug logs
    print(f"[RESMON_7d] Assigned IPs: {sorted(assigned_ip_set)}")
    print(f"[RESMON_7d] Seen IPs: {sorted(seen_ips)}")
    for ip in ghosts:
        print(f"[RESMON_7d] 👻 Ghost detected in process {pid}: {ip}")

    # Write ghost artifact if any
    if ghosts:
        ghost_file = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}_{ts}.json")
        try:
            with open(ghost_file, "w") as f:
                json.dump(ghosts, f, indent=2)
            print(f"[RESMON_7d] Ghost artifact written: {ghost_file}")
        except Exception as e:
            print(f"[RESMON_7d] Failed to write ghost artifact: {e}")

    return ghosts







## Global function get_watchdog_timeout() to calculate the actual adaptive WATCHDOG_TIMEOUT based upon the parameters below
## This is code block2 for adaptive WATCHDOG_TIMEOUT
def get_watchdog_timeout(node_count, instance_type, peak_retry_attempts):
    base = 15
   
    # use a scale map instead of just scale.

    SCALE_MAP = {
        "t2.micro": 0.15,
        "t2.small": 0.12,
        "default": 0.1
    }
    scale = SCALE_MAP.get(instance_type, SCALE_MAP["default"])

    #scale = 0.15 if instance_type == "micro" else 0.1
   
    contention_penalty = min(30, peak_retry_attempts * 2)  # up to +30s
    


    adaptive_timeout = math.ceil(base + scale * node_count + contention_penalty)
    return max(18, adaptive_timeout) # set the base to 30 seconds for testing


    #return int(base + scale * node_count + contention_penalty)
    
    #return math.ceil(base + scale * node_count + contention_penalty)

#The node_count is the total number of nodes deployed during the execution run
#The instance_type is the instance type of the EC2 nodes (for example t2.micro)
#The peak_rety_attempts will be calcualted per process based upon API contention with AWS (this will be done by a modified
#retry_with_backoff function)
#The scale is a multiplier that is based upon the instance type (higher value for smaller vCPU instance type)
#For initial testing with 512 nodes this will be set to 0.11 so that the watchdog timeout will remain at the original 90 
#second baseline







## --- COMMENTED OUT FOR DISK-HANDOFF write-to-disk WORKFLOW ---
## all_process_registries is NOT shared between processes and this approach does not work 

### This is the global all_process_registries to collect all the process_registries in the tomcat_worker into one dict 
### this dict will be further processed by aggregate_process_registries (flatten it out to thread registry entries in the dict)
### this final_registry will then be fed into summarize_registry below (in tomcat_worker as well) to collect stats on the tags
### (status) in each of the thread registry entries. We can also export the final_registry to create the 
### final_aggregate_execution_run_registry.json file. This is the file that will be compared to the benchmark_ips_artifact.log
### (the gold standard) to determine if there are any missing ghost threads. All the other threads will be tagged with a 
### failure status or success status (failed + success = total)
#
#all_process_registries = []
#
#
### This is the registry aggregator function. This is required since the setup is multi-processed and the processes do not share 
### memory space. So the process_registry is created in run_test as thread_registry returned from threaded_install, and this is
### called process_registry in tomcat_worker.  We need to save each process process_registry as each process calls run_test in
### the tomcat_worker function, because subsequent processes will overwrite the previous process process_registry(memory not shared)
### tomcat_worker will save them to all_process_registries dict 
### then tomcat_worker will call this function below to flatten out the dict of x proceseses to a list of all the thread registries
### this final_registry wll become the final_aggregate_exection_run_registry.json file for phase3 resurrection
#
#def aggregate_process_registries(all_process_registries):
#    """
#    Aggregates a list of process-level registries into a single unified registry.
#    Each entry in all_process_registries is a dict mapping thread_id -> registry_data.
#    """
#    final_registry = {}
#
#    for process_registry in all_process_registries:
#        for thread_id, registry_data in process_registry.items():
#            if thread_id in final_registry:
#                raise ValueError(f"Duplicate thread_id detected: {thread_id}")
#            final_registry[thread_id] = registry_data
#
#    return final_registry # this is final_aggregate_execution_run_registry.json in the artifact logs.
#


## New aggregate_process_registries for write-to-disk
## Aggregates a list of process-level registries into a single unified registry.
#  Each entry in complete_process_registries is a dict mapping thread_id -> registry_data from the calling function main()
#  


def aggregate_process_registries(complete_process_registries):
    """
    Flatten a list of per-process registry dicts into one unified registry.

    Args:
      complete_process_registries (List[Dict[str, Any]]):
        Each dict maps a thread_uuid → registry_entry for one process.

    Returns:
      Dict[str, Any]: A single dict mapping every unique thread_uuid → its registry_entry.
    """
    final_registry = {}
    for process_registry in complete_process_registries:
        for thread_uuid, entry in process_registry.items():
            if thread_uuid in final_registry:
                raise ValueError(f"Duplicate thread_id: {thread_uuid}")
            final_registry[thread_uuid] = entry
    return final_registry






### New summarize_registry for write-to-disk
### final_registry is from the call below in main
### final_registry = aggregate_process_registries(registries)
### summary = summarize_registry(final_registry)
### aggregate_process_registries above flattens out process dict to a dict of thread id registry entries
#
#def summarize_registry(final_registry):
#    summary = {
#        "total": len(final_registry),
#        "install_success": 0,
#        "gatekeeper_resurrect": 0,
#        "watchdog_timeout": 0,
#        "ssh_initiated_failed": 0,   # placeholder for Patch 8 later
#        "ssh_retry_failed": 0,       # placeholder for patch 8 later
#        "no_tags": 0,
#    }
#    
#
#    #for entry in final_registry.values():
#    #    if entry.get("install_success"):
#    #        summary["install_success"] += 1
#    #    if entry.get("gatekeeper_resurrect"):
#    #        summary["gatekeeper_resurrect"] += 1
#    #    if entry.get("watchdog_timeout"):
#    #        summary["watchdog_timeout"] += 1
#    #    # count entries that lack all outcome tags
#    #    if not any(tag in entry for tag in [
#    #        "install_success",
#    #        "gatekeeper_resurrect",
#    #        "watchdog_timeout"
#    #    ]):
#    #        summary["no_tags"] += 1
#    #
#
#
### summary code was checking `entry.get("install_success")` (a Boolean) instead of `entry["status"] == "install_success"
### this now alligns with status inside registry entries of final_registry
#    for entry in final_registry.values():
#        s = entry.get("status")
#        if s == "install_success":
#            summary["install_success"] += 1
#        elif s == "gatekeeper_resurrect":
#            summary["gatekeeper_resurrect"] += 1
#        elif s == "watchdog_timeout":
#            summary["watchdog_timeout"] += 1
#        elif s == "ssh_initiated_failed":
#            summary["ssh_initiated_failed"] += 1
#        elif s == "ssh_retry_failed":
#            summary["ssh_retry_failed"] += 1
#        else:
#            summary["no_tags"] += 1
#
#
#    return summary
#




## updated def summarize_registry for latest status codes:
## See also the STATUS_TAGS at the top of this module for status tags that can be used with registry_entry.



def summarize_registry(final_registry):
    summary = {
        "total": len(final_registry),
        "install_success": 0,
        "gatekeeper_resurrect": 0,
        "watchdog_timeout": 0,
        "ssh_initiated_failed": 0,
        "ssh_retry_failed": 0,
        "install_failed": 0,  # Newly added
        "stub": 0,            # Newly added for stub registry
        "no_tags": 0
    }

    for entry in final_registry.values():
        s = entry.get("status")
        if s == "install_success":
            summary["install_success"] += 1
        elif s == "gatekeeper_resurrect":
            summary["gatekeeper_resurrect"] += 1
        elif s == "watchdog_timeout":
            summary["watchdog_timeout"] += 1
        elif s == "ssh_initiated_failed":
            summary["ssh_initiated_failed"] += 1
        elif s == "ssh_retry_failed":
            summary["ssh_retry_failed"] += 1
        elif s == "install_failed":
            summary["install_failed"] += 1
        elif s == "stub":
            summary["stub"] += 1
        else:
            summary["no_tags"] += 1

    return summary



## This is the wrapper function for resurrection_monitor_patch7c() to debug the issues that this is having
## There are a few issues: the log and .json files are not being sent out to the gitlab pipeline archive /logs
## The artifacts outside of this function (benchmark_combined.log) are working fine so this problem is inside the function
## Make sure to change the call to resurrection_monitor_patch7c() inside tomcat_worker() to 
## run_resurrection_monitor_diag(process_registry)
## This function was used for debugging and is currently not in use.


def run_resurrection_monitor_diag(process_registry):
    import os
    import multiprocessing
    import traceback

    pid = multiprocessing.current_process().pid
    log_dir = "/aws_EC2/logs"

    # === Execution Proof ===
    print(f"[WRAPPER_HEARTBEAT] 🔧 Wrapper function triggered for PID {pid}")
    heartbeat_probe = os.path.join(log_dir, f"wrapper_probe_{pid}.txt")
    try:
        with open(heartbeat_probe, "w") as f:
            f.write(f"Wrapper executed for PID {pid}\n")
    except Exception as e:
        print(f"[ERROR] 🧨 Failed to write wrapper heartbeat file: {e}")

    # === Console Logs ===
    print(f"[RES_MONITOR] 🔍 Starting resurrection monitor for PID {pid}")
    print(f"[FILE_SCAN] 📂 Pre-monitor contents of {log_dir}:")

    try:
        files = os.listdir(log_dir)
        for fname in files:
            print(f"[FILE_SCAN] └─ {fname}")
        if not files:
            print(f"[FILE_SCAN] ⚠️ No files found in log directory prior to monitor execution")
    except Exception as e:
        print(f"[ERROR] 🚨 Failed to read log directory {log_dir}: {e}")

    # === Resurrection Monitor Execution ===
    try:
        resurrection_monitor_patch8(process_registry)
        print(f"[PATCH7D] ✅ resurrection_monitor_patch7d executed successfully for PID {pid}")
    except Exception as e:
        print(f"[ERROR] 💥 resurrection_monitor_patch7d failed for PID {pid}: {e}")
        traceback.print_exc()

    # === Artifact Summary Check ===
    expected_log_file = os.path.join(log_dir, f"patch7_summary_{pid}.log")
    if os.path.exists(expected_log_file):
        print(f"[SUM_CHECK] 📁 Patch7 summary log exists: {expected_log_file}")
    else:
        print(f"[SUM_CHECK] ⚠️ Patch7 summary log MISSING for PID {pid}")





# COMMENT this out for now so that i can test the benchmark.log artifact below
# will do a dual logger later to accomodate this.

#logging.basicConfig(level=logging.CRITICAL, format='%(processName)s: %(message)s')



## This code is to address the (RequestLimitExceeded) when calling the AuthorizeSecurityGroupIngress operation 
## Too many API calls are hitting the threshold from AWS. 
## will need to wrap the calls to authorize_security_group_ingress in this function below that implements
## exponential backoff as AWS recommends.
## This issue resurfacing at 200 concurrent processes. Try increasing the max_retires from 5 to 10 to see if it resolves the
## issue. If it does may need to introduce a more dynamic form of the exponential backoff.
## NOTE: do not increase delay because that will affect the hybrid pooled/nonpooled scenarios (desired_count < total processes)
## and that would be slowing them down even though they do not need API backoff increased. Only use max_retries increase.

#def retry_with_backoff(func, max_retries=15, base_delay=1, max_delay=10, *args, **kwargs):
#    for attempt in range(max_retries):
#        try:
#            return func(*args, **kwargs)
#        except botocore.exceptions.ClientError as e:
#            if 'RequestLimitExceeded' in str(e):
#                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
#                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
#                time.sleep(delay)
#            else:
#                raise
#    raise Exception("Max retries exceeded for AWS API call.")


## REVISED retry_with_backoff to support adaptive WATCHDOG_TIMEOUT (Code block 1 of 3)
def retry_with_backoff(func, max_retries=15, base_delay=1, max_delay=10, *args, **kwargs):
    """
    Wraps an AWS API call with exponential backoff on RequestLimitExceeded,
    and updates `max_retry_observed` to the highest retry index seen in this process.
    This max_retry_observed is set per process for all the threads in that process based upon the code below which is called
    from 3 blocks of code in tomcat_worker()
    """
    global max_retry_observed

    for attempt in range(max_retries):
        try:
            result = func(*args, **kwargs)

            # record the highest attempt index (0-based) that succeeded
            with retry_lock:
                max_retry_observed = max(max_retry_observed, attempt)

            return result

        except botocore.exceptions.ClientError as e:
            if "RequestLimitExceeded" in str(e):
                # exponential backoff + jitter
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                # re-raise any other client errors
                raise

    # We exhausted all attempts—capture that too
    with retry_lock:
        max_retry_observed = max(max_retry_observed, max_retries)

    raise Exception("Max retries exceeded for AWS API call.")








# this function run_module is not used here but in the master python script, but may use this function here at some later
# time
def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    with open(module_script_path) as f:
        code = f.read()
    exec(code, globals())
    logging.critical(f"Completed module script: {module_script_path}")







#### This block of code is for the benchmarking wrapper function the the ThreadPoolExecutor in t#omcat_worker() function
#### below. This has the run_test() function that is used in it as well as the  benchmark() func#tion that run_test
#### requires to run specific benchmarks on the ThreadPoolExecutor                              #
#### These functions need to be accessible globally in this module.                             #
#### This is using a custom contextmanager as defined below with yield split as below.          #
#import time
#import psutil
#import logging
#import os
#import multiprocessing
#import random
#from contextlib import contextmanager
#import uuid
#from io import StringIO

# Setup per process logging
# This needs to be run for each process, i.e. each process call to tomcat_worker below. 
# This function will be used in tomcat_worker per process when the ThreadPoolExecutor chunk is run

#The .gitlab-ci.yml deploy now runs the docker container to mount
# aws_EC2/logs/benchmark.log to the gitlab_project_directory/logs/benchmark.log, so need to create this directory in the 
# docker container and log to logs/benchmark.org.  This is mapped to gitlab directory/logs and from there gitlab pipeline
# can get the artifact for this pipeline as benchmark.log

#def setup_logging():
#    pid = multiprocessing.current_process().pid
#    log_path = f'/aws_EC2/logs/benchmark_{pid}.log'
#    os.makedirs(os.path.dirname(log_path), exist_ok=True)
#
#
#    logging.basicConfig(
#        filename=log_path,
#        level=logging.INFO,
#        format='%(asctime)s - %(process)d - %(message)s',
#        force=True  # Python 3.8+ only
#    )
#    #logging.info("Logging initialized in process.")



def setup_logging():
    pid = multiprocessing.current_process().pid
    unique_id = uuid.uuid4().hex[:8]
    log_path = f'/aws_EC2/logs/benchmark_{pid}_{unique_id}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    print(f"[DEBUG] Setting up logging for PID {pid} with unique ID {unique_id} at {log_path}")


    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        #format='%(asctime)s - %(process)d - %(message)s',
        format='%(asctime)s - %(process)d - %(threadName)s - %(message)s',

        force=True  # Python 3.8+ only
    )
    #logging.info("Logging initialized in process.")




    # Print the actual path to the log file
    print("Real path Logging to:", os.path.realpath(log_path))

    # Print the absolute path to a relative filename (for comparison/debugging)
    print("Absolute path Logging to:", os.path.abspath("benchmark.log"))

## ADD buffering to the setup_logging so that in tomcat_worker_wrapper (see further below) we can only create the log
## file if there is content. This is required since adding the code for distinguishing between the start up processes
## and the pooled processes with respect to per process logging. Otherwise setup_logging() will create an empty log file
## for each PID/uuid file combination. make sure to add from io import StringIO to the imports
## The stream handler has replaced the basicConfig logging and this is better for multi-process logging.
#def setup_logging():
#    pid = multiprocessing.current_process().pid
#    unique_id = uuid.uuid4().hex[:8]
#    log_path = f'/aws_EC2/logs/benchmark_{pid}_{unique_id}.log'
#    os.makedirs(os.path.dirname(log_path), exist_ok=True)
#
#    print(f"[DEBUG] Setting up logging for PID {pid} with unique ID {unique_id} at {log_path}")
#
#    # Create a memory buffer for logging
#    log_buffer = StringIO()
#    buffer_handler = logging.StreamHandler(log_buffer)
#    formatter = logging.Formatter('%(asctime)s - %(process)d - %(message)s')
#    buffer_handler.setFormatter(formatter)
#
#    logger = logging.getLogger()
#    logger.handlers = []  # Clear any existing handlers
#    logger.setLevel(logging.INFO)
#    logger.addHandler(buffer_handler)
#
#    return logger, log_buffer, log_path
#
#
#    # Print the actual path to the log file
#    print("Real path Logging to:", os.path.realpath(log_path))
#
#    # Print the absolute path to a relative filename (for comparison/debugging)
#    print("Absolute path Logging to:", os.path.abspath("benchmark.log"))
#




## The various models for the per process logging are further down below. With model4 there is still an issue with
## multi-processing pooling whereby the queued processes(pooled) are not getting a log file. This is because of
## process re-use by the multiprocessing pooler. The fix involves:
# Wrap the tomcat_worker and use the wrap function tomcat_worker from the main() call to tomcat_worker as tomcat_worker_wrapper
# - `tomcat_worker_wrapper()` is called **for every task**, even if the process is reused.
# - `setup_logging()` is guaranteed to run at the start of each task, ensuring a fresh log file is created for each process execution.
# - Since using `force=True` in `basicConfig()`, it will override any previous logging config in that process.

#def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
#    setup_logging()  # Ensure logging is reconfigured for each task
#    return tomcat_worker(instance_info, security_group_ids, max_workers)


def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
    pid = multiprocessing.current_process().pid
    print(f"[DEBUG] Wrapper called for PID {pid}")
    setup_logging()
    return tomcat_worker(instance_info, security_group_ids, max_workers)


## UPDATE the tomcat_worker_wrapper to use the buffer appraoch with the setup_logging() function so that we no longer
## get empty log files for the PID/uuid files for multi-processing logging with the pooled processes
#def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
#    pid = multiprocessing.current_process().pid
#    print(f"[DEBUG] Wrapper called for PID {pid}")
#
#    logger, log_buffer, log_path = setup_logging()
#
#    try:
#        return tomcat_worker(instance_info, security_group_ids, max_workers)
#    finally:
#        if log_buffer.tell() > 0:
#            with open(log_path, 'w') as f:
#                f.write(log_buffer.getvalue())





## MODEL 1: with this multi-process logging add the pid to the print logs to make things clearer
## This does not have periodic sampling
#@contextmanager
#def benchmark(test_name):
#    process = psutil.Process()
#    start_time = time.time()
#    start_swap = psutil.swap_memory().used / (1024 ** 3)
#    start_cpu = process.cpu_percent(interval=1)
#
#    pid = multiprocessing.current_process().pid
#    logging.info(f"[PID {pid}] START: {test_name}")
#    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
#    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")
#
#    yield
#
#    end_time = time.time()
#    end_swap = psutil.swap_memory().used / (1024 ** 3)
#    end_cpu = process.cpu_percent(interval=1)
#
#    logging.info(f"[PID {pid}] END: {test_name}")
#    logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
#    logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
#    logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")
#
#def run_test(test_name, func, *args, **kwargs):
#    with benchmark(test_name):
#        func(*args, **kwargs)




### MODEL 2: Add periodic sampling using the sample_metrics thread for CPU and memory usage during the test
### sampler_thread invokes sample_metrics now within the benchmark function which is called from 
### run_test through the context manager
### run_test is invoked by tomcat_worker and calls threaded_install which does the ThreadPoolExecutor on the chunk of data
#def sample_metrics(stop_event, pid, interval):
#    process = psutil.Process()
#    while not stop_event.is_set():
#        cpu = process.cpu_percent(interval=None)
#        swap = psutil.swap_memory().used / (1024 ** 3)
#        logging.info(f"[PID {pid}] Sampled CPU usage: {cpu:.2f}%")
#        logging.info(f"[PID {pid}] Sampled swap usage: {swap:.2f} GB")
#        stop_event.wait(interval)
#
#@contextmanager
#def benchmark(test_name, sample_interval=60):
#    process = psutil.Process()
#    start_time = time.time()
#    start_swap = psutil.swap_memory().used / (1024 ** 3)
#    start_cpu = process.cpu_percent(interval=1)
#
#    pid = multiprocessing.current_process().pid
#    logging.info(f"[PID {pid}] START: {test_name}")
#    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
#    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")
#
#    stop_event = threading.Event()
#    sampler_thread = threading.Thread(target=sample_metrics, args=(stop_event, pid, sample_interval))
#    sampler_thread.start()
#
#    try:
#        yield
#    finally:
#        stop_event.set()
#        sampler_thread.join()
#
#        end_time = time.time()
#        end_swap = psutil.swap_memory().used / (1024 ** 3)
#        end_cpu = process.cpu_percent(interval=1)
#
#        logging.info(f"[PID {pid}] END: {test_name}")
#        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
#        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
#        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")
#
## set the sample_interval here. Default is 60 seconds
#def run_test(test_name, func, *args, sample_interval=120, **kwargs):
#    with benchmark(test_name, sample_interval=sample_interval):
#        func(*args, **kwargs)
#


### MODEL 3: RANDOMIZED log sampler. The periodic sampler above is inducing sample contention amongst the processes. Use a
### randomizer to sample once during the process run so that the sampling between the processes will not collide.
### this will be useful when hyper-scaling the number of processes.
### Initially start with randomizer between 50  and 250 seconds for 200 slot seconds.  
#def sample_metrics_once_after_random_delay(pid, delay):
#    time.sleep(delay)
#    process = psutil.Process()
#    cpu = process.cpu_percent(interval=None)
#    swap = psutil.swap_memory().used / (1024 ** 3)
#    logging.info(f"[PID {pid}] Random-sample CPU usage: {cpu:.2f}% after {delay:.1f}s")
#    logging.info(f"[PID {pid}] Random-sample swap usage: {swap:.2f} GB")
#
#@contextmanager
#def benchmark(test_name, sample_delay):
#    process = psutil.Process()
#    start_time = time.time()
#    start_swap = psutil.swap_memory().used / (1024 ** 3)
#    start_cpu = process.cpu_percent(interval=1)
#
#    pid = multiprocessing.current_process().pid
#    logging.info(f"[PID {pid}] START: {test_name}")
#    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
#    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")
#
#    sampler_thread = threading.Thread(
#        target=sample_metrics_once_after_random_delay,
#        args=(pid, sample_delay)
#    )
#    sampler_thread.start()
#
#    try:
#        yield
#    finally:
#        sampler_thread.join()
#
#        end_time = time.time()
#        end_swap = psutil.swap_memory().used / (1024 ** 3)
#        end_cpu = process.cpu_percent(interval=1)
#
#        logging.info(f"[PID {pid}] END: {test_name}")
#        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
#        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
#        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")
#
#def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, **kwargs):
#    delay = random.uniform(min_sample_delay, max_sample_delay)
#    with benchmark(test_name, sample_delay=delay):
#        func(*args, **kwargs)
#
#


## MODEL 4: Use the radomizer model 4 above,  but only sample 10% of the processes:
def sample_metrics_once_after_random_delay(pid, delay):
    time.sleep(delay)
    process = psutil.Process()
    cpu = process.cpu_percent(interval=None)
    swap = psutil.swap_memory().used / (1024 ** 3)
    logging.info(f"[PID {pid}] Random-sample CPU usage: {cpu:.2f}% after {delay:.1f}s")
    logging.info(f"[PID {pid}] Random-sample swap usage: {swap:.2f} GB")

@contextmanager
def benchmark(test_name, sample_delay=None):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    sampler_thread = None
    if sample_delay is not None:
        sampler_thread = threading.Thread(
            target=sample_metrics_once_after_random_delay,
            args=(pid, sample_delay)
        )
        sampler_thread.start()

    try:
        yield
    finally:
        if sampler_thread:
            sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)

        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")


## This needs to be slightly modified for the patch7c to return the thread_registry from threaded_install
## run test is invoked with func threaded_install and this now returns the thread_registry which will later 
## be assigned process_registry to be consumed by resurrection_monitor_patch7c

## This has been modified again to support adaptive WATCHDOG_TIMEOUT. This is code block3 of that implementation.

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):
    
    # 1) decide whether to sample metrics
    delay = None
    
    if random.random() < sample_probability:
        delay = random.uniform(min_sample_delay, max_sample_delay)

    # 2) wrap in benchmark context
    with benchmark(test_name, sample_delay=delay):
    
        #func(*args, **kwargs)

        # get rid of double result. This is causing 2 install tomcat.   Use the one at the end after the new WATCHDOG_TIMEOUT
        # code. Make sure to move the print to after the real result below. Don't leave it here!!!
        #result = func(*args, **kwargs)
        #print(f"[TRACE][run_test] func returned type: {type(result)}")
        
        # need to determine what is being returned by func which is threaded_install in this case so that 
        # if isinstance(result, list): loop below is executed.
        # result is the return from threaded_install which is thread_registry the process level registry. If multi-threaded there
        # should be an entry for each thread/IP/EC2 instance in the registry.




        # ─── NEW BLOCK  Code block3 for adaptive WATCHDOG_TIMEOUT ───
        # By the time this function is called in tomcat_worker all the  retry_with_backoff calls have happened already in tomcat_worker
        # so max_retry_observed is now set for this process.(modified retry_with_backoff calculates this as max_retry_observed
        # We can compute the dynamic WATCHDOG_TIMEOUT from here with call to get_watchdog_timeout

        global WATCHDOG_TIMEOUT

        # extract node_count from the first arg to func (threaded_install)
        # node_count = len(args[0]) if args and isinstance(args[0], (list, tuple)) else 0
        # instance_type = os.getenv("INSTANCE_TYPE", "micro")


        # Pull node count and instance type from environment
        node_count = int(os.getenv("max_count", "0"))  # fallback to 0 if not set
        instance_type = os.getenv("instance_type", "micro")

        # call the get_watchdog_timeout to calculate the adaptive WATCHDOG_TIMEOUT value
        # max_retry_observed is iteratively set  in the modified retry_with_backoff functin.
        WATCHDOG_TIMEOUT = get_watchdog_timeout(
            node_count=node_count,
            instance_type=instance_type,
            peak_retry_attempts=max_retry_observed
        )


        print(f"[Dynamic Watchdog] [PID {os.getpid()}] "
              f"instance_type={instance_type}, node_count={node_count}, "
              f"max_retry={max_retry_observed} → WATCHDOG_TIMEOUT={WATCHDOG_TIMEOUT}s")



        # ─── actual call to threaded_install which returns thread_registry which is process_registry ───
        # thread_registry will be assigned the important process_registry in tomcat_worker() the calling function of run_test

        result = func(*args, **kwargs)
        print(f"[TRACE][run_test] func returned type: {type(result)}")        

        return result  # move this within the benchnark context





## comment out the inline run_test aggregator. This won't work. The processes have their own memory space. Not shared. So even this
## aggregate_registry is overwritten with each sucessive process that runs the run_test. So it never holds more than the last process
## to execute in the end of the execution run. Alternatives are a post execution aggregator (will do this) or using a Manager().dict()`
## But Manager dict uses IPC between processes and that creates a lot of overhead. It is also hard to debug and can get mutations in 
## the dictionary if a lot of processes access it at the same time.   
## Note that there is still a return result at the very bottom that returns the thread_registy for each process that runs this run_test
## These process level registries will be aggregated post execution with the function aggregate_process_registries() a global functino
## defined at the top of this module ^^^^^^.

#    print("[TRACE][run_test] Starting aggregator logic")
#
#
#
#    # So the threaded_isntall is returning a dict, i.e. a single dict so the logic needs to handle a single dict
#    # IF it is a list of dicts (dict) then the logic below will also integrate these registry entries as weill into aggregate_registry
#
#
#    aggregate_registry = {}
#
#    print("[TRACE][run_test] Entered run_test()")
#
#    if isinstance(result, dict):
#        print("[TRACE][run_test] Detected single dict result")
#        print(f"[TRACE][run_test] aggregate_registry BEFORE update: {len(aggregate_registry)}")
#        aggregate_registry.update(result)
#        print(f"[TRACE][run_test] aggregate_registry AFTER update: {len(aggregate_registry)}")
#        print(f"[TRACE][run_test] Keys: {list(aggregate_registry.keys())}")
#        for uuid, entry in aggregate_registry.items():
#            print(f"[TRACE][run_test] UUID {uuid} | IP: {entry.get('public_ip')} | Status: {entry.get('status')}")
#
#    elif isinstance(result, list):
#        print("[TRACE][run_test] Detected list of dicts result")
#        for thread_registry in result:
#            print(f"[TRACE][run_test] thread_registry keys: {list(thread_registry.keys())}")
#            print(f"[TRACE][run_test] aggregate_registry BEFORE update: {len(aggregate_registry)}")
#            aggregate_registry.update(thread_registry)
#            print(f"[TRACE][run_test] aggregate_registry AFTER update: {len(aggregate_registry)}")
#            print(f"[TRACE][run_test] Keys: {list(aggregate_registry.keys())}")
#
#
#
#        # ✅ Aggregation trace
#        print(f"[TRACE][run_test] Aggregate registry has {len(aggregate_registry)} entries")
#        for uuid, entry in aggregate_registry.items():
#            if entry.get("status") == "install_success":
#                print(f"[TRACE] UUID {uuid} | IP: {entry.get('public_ip')} ✅")
#
#        # 🧪 Forensic validator: compare aggregate_registry IPs to benchmark_ips_artifact.log
#        try:
#            with open("logs/benchmark_ips_artifact.log") as f:
#                benchmark_ips = set(line.strip() for line in f if line.strip())
#        except FileNotFoundError:
#            benchmark_ips = set()
#            print("[WARN] benchmark_ips_artifact.log not found")
#
#        aggregated_ips = {
#            entry.get("public_ip")
#            for entry in aggregate_registry.values()
#            if entry.get("public_ip") is not None
#        }
#
#        missing_ips = benchmark_ips - aggregated_ips
#        extra_ips = aggregated_ips - benchmark_ips
#
#        print(f"[TRACE] Benchmark IPs: {len(benchmark_ips)} | Aggregated IPs: {len(aggregated_ips)}")
#        print(f"[TRACE] Missing IPs in aggregate: {missing_ips}")
#        print(f"[TRACE] Extra IPs not in benchmark: {extra_ips}")
#



#    return result
#    this was outside of the "with benchmark" context. Not terrible but not ideal. See above. Move this
#    inside of the benchmark context








## Add this helper function for the describe_instance_status as the DescribeInstanceStatus method can only handle
## 100 at a time. Need this to test the 100+ use case
def describe_instances_in_batches(ec2_client, instance_ids):
    all_statuses = []
    for i in range(0, len(instance_ids), 100):
        batch = instance_ids[i:i + 100]
        response = ec2_client.describe_instance_status(InstanceIds=batch, IncludeAllInstances=True)
        all_statuses.extend(response['InstanceStatuses'])
    return all_statuses







# NEW1 This is an improvement on wait_for_all_public_ips with exponential backoff and also include private ips and 
# instance_ids in the array (list of dictionaries) instance_ips like with my original code.

# With t2.micro increase timeout to 180. With t2.small or t3.small use 120 second timeout
def wait_for_all_public_ips(ec2_client, instance_ids, exclude_instance_id=None, timeout=180):
    """
    Waits for all EC2 instances (excluding the controller) to receive public IPs.
    Uses exponential backoff for retries and includes private IPs in the result.
    """
    
    # DEBUG INSTRUMENTATION START
    print("[DEBUG ENTRY1] wait_for_all_public_ips")
    print(f"    raw instance_ids:         {instance_ids}")
    print(f"    exclude_instance_id arg:  {exclude_instance_id!r}")
    # 




    start_time = time.time()
    attempt = 0
    delay = 5  # initial delay in seconds

    # Filter out the controller instance if provided
    filtered_instance_ids = [iid for iid in instance_ids if iid != exclude_instance_id]

    


    # ADDITIONAL DEBUG LOGS (right after filtering)
    print(f"[DEBUG1] filtered_instance_ids → {filtered_instance_ids}")
    print(f"[DEBUG1] count of filtered IDs → {len(filtered_instance_ids)}")
    # 

    if not filtered_instance_ids:
        print("[ERROR1] filtered_instance_ids is empty—nothing to poll!")
        raise ValueError("No instance IDs left after exclude; check your caller.")

   



    while time.time() - start_time < timeout:
        attempt += 1
        print(f"[DEBUG] Attempt {attempt}: Checking public IPs...")

        response = ec2_client.describe_instances(InstanceIds=filtered_instance_ids)
        
        # 🔍 Add these debug prints here
        print(f"[DEBUG1] Launch response keys → {response.keys()}")
        print(f"[DEBUG1] Number of Reservations → {len(response['Reservations'])}")
        for r in response['Reservations'][:2]:  # limit to first 2 for brevity
            for inst in r['Instances'][:2]:
                print(f"[DEBUG1] Instance ID → {inst['InstanceId']}")
                print(f"[DEBUG1] Public IP → {inst.get('PublicIpAddress')}")
                print(f"[DEBUG1] State → {inst['State']['Name']}")
        # 🔍 End debug block
     




        instance_ips = []

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                public_ip = instance.get('PublicIpAddress')
                private_ip = instance.get('PrivateIpAddress')
                instance_id = instance['InstanceId']

                if public_ip:
                    instance_ips.append({
                        'InstanceId': instance_id,
                        'PublicIpAddress': public_ip,
                        'PrivateIpAddress': private_ip
                    })

        if len(instance_ips) == len(filtered_instance_ids):
            print(f"[INFO] All {len(instance_ips)} instances have public IPs.")
            return instance_ips

        print(f"[DEBUG] {len(instance_ips)} of {len(filtered_instance_ids)} instances have public IPs. Retrying in {delay} seconds...")
        time.sleep(delay)
        delay = min(delay * 2, 30)  # exponential backoff with a max delay of 30 seconds

    raise TimeoutError(f"Not all instances received public IPs within {timeout} seconds.")


# === wait_for_instance_visibility ===
# Waits until all expected EC2 instances are visible via describe_instances.
# Uses exponential backoff and filters by tag and state.
# Returns a list of instance IDs once the expected count is reached.
def wait_for_instance_visibility(ec2_client, expected_count, tag_key, tag_value, timeout=180):
    start_time = time.time()
    delay = 5
    attempt = 0

    while time.time() - start_time < timeout:
        attempt += 1
        print(f"[VISIBILITY] Attempt {attempt}: Checking for {expected_count} instances with tag {tag_key}={tag_value}")

        response = ec2_client.describe_instances(
            Filters=[
                {'Name': f'tag:{tag_key}', 'Values': [tag_value]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running']}
            ]
        )

        instance_ids = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_ids.append(instance['InstanceId'])

        print(f"[VISIBILITY] Found {len(instance_ids)} instances")

        if len(instance_ids) >= expected_count:
            print("[VISIBILITY] All expected instances are visible")
            return instance_ids

        time.sleep(delay)
        delay = min(delay * 2, 30)

    raise TimeoutError(f"Only {len(instance_ids)} of {expected_count} instances visible after {timeout} seconds")


# === orchestrate_instance_launch_and_ip_polling ===
# High-level wrapper that:
# 1. Waits for all EC2 instances to be visible
# 2. Excludes the controller node if provided
# 3. Polls for public IPs using wait_for_all_public_ips()
# Returns structured IP data for all worker instances.
def orchestrate_instance_launch_and_ip_polling(exclude_instance_id=None):
    # Load AWS credentials and region from .env
    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("region_name")

    # Create a session and EC2 client
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    ec2_client = session.client('ec2')




    # Pull node count from .env
    node_count = int(os.getenv("max_count", "0"))  # fallback to 0 if not set
    logging.info(f"[orchestrator] Launching with node_count={node_count}")

    # Tag used to identify launched instances
    tag_key = 'BatchID'
    tag_value = 'test-2025-08-13'

    # Step 1: Wait for all instances to be visible
    instance_ids = wait_for_instance_visibility(ec2_client, node_count, tag_key, tag_value)

    # Step 2: Exclude controller if needed
    if exclude_instance_id:
        instance_ids = [iid for iid in instance_ids if iid != exclude_instance_id]

    # Step 3: Wait for all public IPs
    instance_ip_data = wait_for_all_public_ips(ec2_client, instance_ids)

    return instance_ip_data



###### THIS HAS BEEN REFACTORED and install_tomcat_on_instances is replaced by tomcat_worker for 
#####  multi-processing pooling to deal with hyper-scaling multi-processing cases.

# THIS FUNCTION IS CALLED BY main()
#def install_tomcat_on_instances(instance_ips, security_group_ids):
## import instance_ips and security_group_ids from newly defined main() below
## move these imports to outside of the function as we will be adding more functions to this file (a main() wrapper around
## this function (see below)
##    import boto3
##    from dotenv import load_dotenv
##    import os
##    import paramiko
##    import time
##    from concurrent.futures import ThreadPoolExecutor, as_completed
##    import json
##    import sys
#
#
#    # Load environment variables from the .env file
#    load_dotenv()
#
#    # Set variables from environment
#    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
#    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
#    region_name = os.getenv("region_name")
#    image_id = os.getenv("image_id")
#    instance_type = os.getenv("instance_type")
#    key_name = os.getenv("key_name")
#    min_count = os.getenv("min_count")
#    max_count = os.getenv("max_count")
#    aws_pem_key = os.getenv("AWS_PEM_KEY")
#
#
#
#
## Move the instance public_ip code out of the install_tomcat_on_instances and into main() below
## main() will be executed first and will ensure all instances are up and have public_ips
##
##    # Define the instance ID to exclude (the EC2 controller)
##    exclude_instance_id = 'i-0aaaa1aa8907a9b78'
##
##
##
##    # Debugging: Print the value of exclude_instance_id
##    print(f"exclude_instance_id: {exclude_instance_id}")
##
##
##
##
##    ## add this because getting a scope error in the multi-threaded setup with exclude_instance_id
##    ## if it prints out ok then it is not a scope or access issue.
##    ## Ensure exclude_instance_id is accessible within the threads
##    #def check_exclude_instance_id():
##    #    print(f"exclude_instance_id: {exclude_instance_id}")
##    #
##    #with ThreadPoolExecutor(max_workers=len(public_ips)) as executor:
##    #    futures = [executor.submit(check_exclude_instance_id) for _ in range(len(public_ips))]
##    #    for future in as_completed(futures):
##    #        future.result()
##    #
##
#
#    # Establish a session with AWS
#    session = boto3.Session(
#        aws_access_key_id=aws_access_key,
#        aws_secret_access_key=aws_secret_key,
#        region_name=region_name
#    )
#
#    # Create an EC2 client
#    my_ec2 = session.client('ec2')
#
#
#











# ------------------ RESURRECTION MONITOR (POST-HOOK LOGGER) ------------------
# Purpose: After all tomcat installations finish inside tomcat_worker(),
#          this scans the resurrection registry for timeout patterns or stalled attempts.
# Scope:   Evaluates centralized registry state across all threads in the process
# Output:  Writes flagged thread data to /aws_EC2/logs/resurrection_registry_log.json
#          for GitLab artifact tracking, postmortems, or ML introspection in Phase 4
# ---------------------------------------------------------------------------

import os
import json
import multiprocessing
import threading
import time
import uuid
import copy
import traceback
from datetime import datetime




## REVISION 6: resurrection_monitor_patch8

## Patch8 is below.  This is a patch to do the following changes in 3 stages to various functions:

##### Stage1:
#Remove `update_resurrection_registry`. Resurrection tagging should be completely centralized
#- Refactor `read_output_with_watchdog` to return output and status only: `(stdout, stderr, status)` only
#- Move all resurrection tagging logic out of `install_tomcat`.
#- Let `resurrection_monitor_patch8` handle all resurrection logic based on `process_registry`
#
#
#
##### Stage2:
#Move Resurrection Candidate Logic to `resurrection_monitor_patch8` This will be a process level resurrection candidate json
#file. There is already an aggregate resurrection candidate json file artifact.
#
#This resurrection candidate process level file will be done from the process_registry:
#
#- Scan `process_registry` in real time for `status != "install_success"`.
#- Tag resurrection candidates based on process-level heuristics.
#- Eliminate `resurrection_registry` entirely.
#
#Inside `resurrection_monitor_patch8`, scan using the logic !=install_success tentatively (this will cover all stub and 
#install_failed registry threads, etc.)
#
#
#```
#for thread_uuid, entry in process_registry.items():
#    if entry.get("status") != "install_success":
#        # Tag as resurrection candidate
#```
#
#This eliminates the need for a separate `resurrection_registry` and keeps all resurrection logic in one place.
#
#
#
#
##### Stage3:
#Modularize Resurrection Gatekeeper (currently called from install_tomcat, but it needs to be called from resurrection_monitor)
#- Refactor `resurrection_gatekeeper()` to be reusable outside `install_tomcat`.
#- Use it in `resurrection_monitor_patch8` to decide which threads to resurrect. Bascially all of the install_failed and most 
#if not all of the stubs (i.e., not install_success registry_entry threads)
#- Filter resurrection candidates
#- Decide whether to retry based on tags like `"install_failed"` or `"stub"`
#- This sets the stage for Phase3 of this project where the threads will be resurrected.
#





## Patch7d is below. This is to fix the ghost and candidate resurrection tagging and the json logging for both
## NOTE that this is per process level tagging and logging of the threads for ghosts and candidates
## main() does the logging for these at the aggregate level (for all processes) and that's working fine.




# ------------------ PATCH7C: THREAD-LOCAL RESURRECTION MONITOR ------------------
# Goal:   Create isolated thread-level logs for postmortem analysis and retry heuristics.
# Scope:  Operates on per-process registry (process_registry) assembled via tomcat_worker()
# Output: resurrection_registry_log_{pid}.json scoped to thread-local attempts
# -------------------------------------------------------------------------------
# Design note: Built atop Patch7b with scoped overrides to preserve thread-local logging clarity.

# === PATCH7C === Resurrection Monitor: Thread-Local Aggregation
#def resurrection_monitor_patch7c(log_dir="/aws_EC2/logs"):
# resurrection_monitor_patch7c needs to accept process_registry from tomcat_worker() now for patch7c
# process_registry has all IPs for multi-threaded process
# replace all resurrection_registry calls with process_registry BUT only in resurrection_monitor_patch7c function that gets
# the process_registry from the run_test call to threaded_install. The other resurrection_montior are global and are not
# to be changed.





######## patch7d1 ##########
#For patch7d we need to pass the instance_info from the higher level functions (tomcat_worker and tomcat_worker_wrapper) to
#the resurrection_monitor. instance_info is derived from tomcat_worker_wrapper which is called from main with the 
#  args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks] . This chunk is the chunk of ips that is 
# assigned to the pariticular process that will be run.  

# In main(), The chunk is derived from the instance_ips and the parameters as shown below:
# chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
# and this enumeration: for i, chunk in enumerate(chunks):   
# along with the args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks] 
# The arg list with chunk is passed to tomcat_worker_wrapper as `instance_info` : 
# `def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers)`

# main uses this function call to tomcat_worker_wrapper using the args_list above:
# `with multiprocessing.Pool(processes=desired_count) as pool:`
#            'pool.starmap(tomcat_worker_wrapper, args_list)`

# each process receives a `chunk` of IPs via `instance_info`, and that chunk is the authoritative list of IPs that the  process
# is responsible for. This is the  per-process GOLD standard analagous to the benchmark_ips at the aggregate level 
# (benchmark_ips_artifact.log)

# assigned_ips are the actual chunk ips assigned to this process, i.e. chunk or instance_info
# These are passed from the calling function tomcat_worker to resurrection_monitor_patch7d(process_registry, instance_info)
# THus instance_info is assigned_ips within this function
############################


######## patch 7d2 ##########

# modularize and restructure the resurrection_monitor as it has a lot of old legacy code to be cleaned out and it also
# needs to be more organized. Will start with the hydrate_benchmark_ips() and the detect_ghosts() helper functions (global
# at the top of this python module. After that will continue to modularize the function as a lead in to patch8 which will
# code in the the definitive tags(statuses) of the registry values, both defining them and tagging the registries if
# they fail.   For patch 7d the logs will be noded as [RESMON_7d] for troubleshooting.
# A lot of the legacy code will be commented out or removed.
############################


#def resurrection_monitor_patch7d(process_registry, log_dir="/aws_EC2/logs"):
#def resurrection_monitor_patch7d(process_registry, assigned_ips, log_dir="/aws_EC2/logs"):
def resurrection_monitor_patch8(process_registry, assigned_ips, log_dir="/aws_EC2/logs"):

    pid = multiprocessing.current_process().pid

    # add timestamp so that if pid is reused (as with hyper-scaling or pooling) the log files can be differentiated for 
    # same pid with timestamp in the log file name.
    # stamp each run so PIDs don’t collide
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")



    # This is the thread_id of the calling thread, and not the thread_ids of the worker threads (That are processing the ip addreses
    # in the chunk_size
    # Since resurrection_monitor_patch7c() is called at the end of tomcat_worker(), which runs in the main thread of the process, this line will return that main thread’s ID
    # This will give us traceability if the thread diagnostics are expanded later on.

    thread_id = threading.get_ident()

    def log_debug(message):
        print(message)

    def timestamp():
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    ## These are the resurrection_registry patch 1-5 logs. These are tagged resurrection candidates for Phase3 implementation
    #log_path = os.path.join(log_dir, f"resurrection_registry_log_{pid}.json")
    # These logs will only be created if there are not successful registry entries in the process (to reduce artifact logging 
    # overhead of blank json files. Note at global level we will create the json/log file regardless as it is only 1 file each for
    # the entire execution.

    #log_path = os.path.join(log_dir, f"resurrection_candidates_registry_{pid}.json")
    # that new path for this  is defined in the new code block at the bottom of this function 


    ## These are teh resurrection ghost patch 7 logs. These are missing registry entires that are in benchmark_ips but are not in the
    ## the registry (missing = benchmark - total registry)
    #ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_log_{pid}.json")
    # This json will only be created if there are ghosts in the process

    #ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}.json")
    # the new path for this is defined in the new code block at the bottom of this function 



    ### This log is now created in main() as part of the aggregation in main()
    ## This is the full snapshot of the registry (all of them: success and fail) per process as part of phase7c
    ## This is multi-threaded and will have all the registry IPs that are being processed by the process (chunk_size number of IPs)
    ## for max_workers threads
    #These is no need to create a process level registry json file for all the processes. It will create a large amount of overhead
    #in terms of artifact files.

    #full_process_snapshot_path = os.path.join(log_dir, f"resurrection_process_registry_snapshot_{pid}.json")


    # Patch 7d2 move this block from the old code for the benchmark_combined_runtime.log generation
    # ------- Combine runtime benchmark logs: filtered for benchmark_combined_runtime.log  -------
    #merged contents from all `benchmark_*.log` PID logs that were created at runtime
    def combine_benchmark_logs_runtime(log_dir, patch7_logger):
        benchmark_combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
        with open(benchmark_combined_path, "w") as outfile:
            for fname in sorted(os.listdir(log_dir)):
                # Only combine true benchmark logs — exclude artifact and combined logs
                if (
                    fname.startswith("benchmark_")
                    and fname.endswith(".log")
                    and "combined" not in fname
                    and not fname.startswith("benchmark_ips_artifact")
                ):
                    path = os.path.join(log_dir, fname)
                    try:
                        with open(path, "r") as infile:
                            outfile.write(f"===== {fname} =====\n")
                            outfile.write(infile.read() + "\n")
                    except Exception as e:
                        patch7_logger.info(f"Skipped {fname}: {e}")
        patch7_logger.info(f"Combined runtime log written to: {benchmark_combined_path}")
        return benchmark_combined_path










## With patch7d2 the resurrection_registry_lock is no longer required:
##- **`process_registry` is per-process and local** — no shared memory, no race conditions.
##- **`resurrection_registry_lock` was originally protecting shared writes** to a global registry or artifact store, but
## these are now being modularized.
##- **Ghost detection and benchmark hydration are read-only operations** — they don’t mutate shared state, so locking is 
##unnecessary.



    flagged = {}
    with resurrection_registry_lock:
        








        # Patch5: This sets the stage for patches 5 and 6.  We are creating total_registry_ips for all ips in registry
        # (i.e. watchdogs that exceeded threshold, our unknown signature ghost, successful fingerprinted ones in install_tomcat,
        # i.e., patch1)
        # and also creating successful_registry_ips (the fingerprinted ones in install_tomcat, i.e. patch1)
        # The objective is with patch 6 and 7 to identify the unknown ghosts in total_registry_ips and then
        # total_registry_ips -(successful_registry_ips) = our elusive ghost threads
        # These ghost threads are threads that have bypassed all conditions so far in the resurrection_gatekeeper and the
        # read_output_with_watchdog functions:
        # - They exited before hitting the stall threshold (`read_output_with_watchdog`)
        #- They bypassed resurrection gatekeeper entirely
        #- No fingerprint means no resurrection log


#        total_registry_ips = set(resurrection_registry.keys())
#        successful_registry_ips = {
#            ip for ip, record in resurrection_registry.items()
#            if record.get("status") == "install_success"
#        }
#
## Replace resurrection_registry with the process_registry for only def resurrection_monitor_patch7c, from threaded_install()
        

       

       # total_registry_ips = set(process_registry.keys()) # process_registry.keys returns uuid and not ip!!
       # successful_registry_ips = {
       #     ip for ip, record in process_registry.items()
       #     if record.get("status") == "install_success"
       # }

        # this syntax returns ips and not uuids. This is what we want.
        total_registry_ips = {
            entry.get("public_ip")
            for entry in process_registry.values()
            if entry.get("public_ip") is not None
        }

        successful_registry_ips = {
            entry.get("public_ip")
            for entry in process_registry.values()
            if entry.get("status") == "install_success"
        }



        # ---------------- Begin Resurrection Registry Scan (patches 2 and 5) ----------------
        
        

        ## We are now keying on thread_uuid. Keying on ip is causing problems. This is a small change as indicated below.

        #for ip, record in process_registry.items():
        #replace process_registry for resurrection_registry for patch7c    
        #for ip, record in resurrection_registry.items():
        
        for thread_uuid, record in process_registry.items():
            ip = record.get("public_ip")
            if not ip:
                continue  # Skip entries without a public IP


            # 🛑 Skip nodes that completed successfully. This is patch2 to address this issue where we are
            # seeing successful installations having resurrection logs created. Patch1, creating a registry
            # fingerprint for successful installs at the end of install_tomcat() did not address this problem
            # Patch1 is at the end of install_tomcat() with install_success fingerprint stamping.
            if record.get("status") == "install_success":
                continue


            reason = "watchdog stall retry threshold" if "timeout" in record["status"] or record["attempt"] >= STALL_RETRY_THRESHOLD else "not in successful_registry_ips"
            record["ghost_reason"] = reason
            flagged[ip] = record
            log_debug(f"[{timestamp()}] Ghost candidate flagged ({reason}): {ip}")


#            if "timeout" in record["status"] or record["attempt"] >= STALL_RETRY_THRESHOLD:
#                flagged[ip] = record
#                log_debug(f"[{timestamp()}] Ghost candidate flagged (watchdog stall retry threshold): {ip}")  
#
#            if ip not in successful_registry_ips:
#                # 👻 Potential ghost thread detected
#                flagged[ip] = record
#                log_debug(f"[{timestamp()}] Ghost candidate flagged (in total_registry_ips): {ip}")
#                



####### UPDATED PATCH 7b to address cross log corruption  ################

#- Prevents `Patch7 Summary` lines from leaking into:
#- `benchmark_*.log` (PID logs)
#- `benchmark_combined.log` (CI-generated artifact log)
#-  Still generates `benchmark_combined_runtime.log` inside the container
#-  Writes artifact logs for registry analysis (`*_artifact.log`)
#-  Logs Patch7 summary to a **dedicated file**, not `stdout`
#-  Fully isolates `patch7_logger` so it never touches shared streams
#

### Updated Patch7 Block 







        # ------- Patch7 Logger Isolation -------
        #This creates a **dedicated logger instance** for Patch7 inside the resurrection monitor, uniquely scoped to the process that’s
        #running it.
        #- The `f"patch7_summary_{pid}"` string makes sure each logger has a unique name per process (e.g., `"patch7_summary_12"`)
        #- This ensures multiple processes don’t reuse or interfere with each other’s loggers — no cross-stream contamination
        #- It allows each resurrection monitor instance to write its own Patch7 summary without touching any shared file or the global
        #logger

        patch7_logger = logging.getLogger(f"patch7_summary_{pid}")
        patch7_logger.setLevel(logging.INFO)
        patch7_logger.propagate = False  # ✋ Prevent root logger inheritance

        # 🗂️ File-based log to avoid stdout interference

        #- `log_dir` is mount target from `.gitlab-ci.yml`,  `/aws_EC2/logs` inside the docker container
        #- `f"patch7_summary_{pid}.log"` gives files like `patch7_summary_12.log`, `patch7_summary_48.log`, etc.
        #- All Patch7 messages will be written **only** to this file — no stdout, no collision with benchmark PID logs
        #This is what enables the safe write

        # summary_handler:
        # Attaches a file-based handler to the logger — meaning all `patch7_logger.info(...)` calls write directly to the file at
        #`summary_log_path`.
        #- This avoids `StreamHandler(sys.stdout)`, which is the usual culprit for GitLab log bleed
        #- It ensures everything written is scoped to one file — line-by-line controlled output

        #summary_log_path = os.path.join(log_dir, f"patch7_summary_{pid}.log")
        # use ts (timestamp) to avoid issues with pid reuse that occurs with hyper-scaling and pooling
        summary_log_path = os.path.join(
          log_dir, f"patch7_summary_{pid}_{ts}.log"
         )


        # Use write mode use mode="w" to overwrite any existing file of the same name (this is for pid reuse case if files are 
        # named the same. This should not happen any longer because timestamp is now added to log filename along with pid)
        #summary_handler = logging.FileHandler(summary_log_path)
        summary_handler = logging.FileHandler(summary_log_path, mode="w")

        summary_formatter = logging.Formatter('[Patch7] %(message)s')
        summary_handler.setFormatter(summary_formatter)
        patch7_logger.addHandler(summary_handler)

        patch7_logger.info("Patch7 Summary — initialized")







        ###### for patch7d2 modularization. Move all of this stuff after the patch7_logger is defined ########
        
        # this will create the benchmark_combined_runtime.log from which we can hydrate benchmark_ips
        benchmark_combined_path = combine_benchmark_logs_runtime(log_dir, patch7_logger)


        ## Patch 7d2 modularization patch changes:
        ## Frist call to hydrate_benchmark_ips global helper function to derive the benchmark_ips GOLD standard thread/ip list that
        ## is required for ghost detection in main() at the aggregate level
        ## Large blocks of the old code for this need to be commented out below. These will be noted with 7d2 in the comments.


        benchmark_ips = hydrate_benchmark_ips(log_dir)

        ## print the artifact that is derived from benchmark_ips,the benchmark_ips_artifact.log that is the runtime list of all
        ## the IPs/theads in the execution run.This is exported out to the gitlab pipeline

        with open(os.path.join(log_dir, "benchmark_ips_artifact.log"), "w") as f:
            for ip in sorted(benchmark_ips):
                f.write(ip + "\n")


        ##  Move this block to here. This will be replaced by the detect_ghosts() helper function.

        ####################
        ## insert patch7d fixes:
        ## This is early code for testing the refactor for ghost detection for 7d2 modularization. This is working well.
        # Extract seen IPs from the current process registry
        seen_ips = {entry["public_ip"] for entry in process_registry.values() if entry.get("public_ip")}
        # Build assigned IPs set from the chunk passed to this process
        assigned_ip_set = {ip["PublicIpAddress"] for ip in assigned_ips}
        # Detect ghosts — IPs assigned to this process but missing from registry
        ghosts = sorted(assigned_ip_set - seen_ips)
        
        # log to console 
        for ip in ghosts:
            print(f"[Patch7d] 👻 Ghost detected in process {pid}: {ip}")

        # log to the artifacts in gitlab
        if ghosts:
            ghost_file = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}_{ts}.json")
            with open(ghost_file, "w") as f:
                json.dump(ghosts, f, indent=2)
         ####################





##### Begin comment out of old benchmark_ips  code.
##### This is the old benchmark_ips generation code.This has been replaced by the global modular function above
##### as part of patch 7d2, hydrate_benchmark_ips()
##### All of this code needs to be commented out after adding the call to hydrate_benchmark_ips early in the 
##### res mon function (see above)


        ## ------- Step 1: Combine runtime benchmark logs: filtered -------
        ##merged contents from all `benchmark_*.log` PID logs that were created at runtime
        #def combine_benchmark_logs_runtime(log_dir):
        #    combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
        #    with open(combined_path, "w") as outfile:
        #        for fname in sorted(os.listdir(log_dir)):
        #            # Only combine true benchmark logs — exclude artifact and combined logs
        #            if (
        #                fname.startswith("benchmark_")
        #                and fname.endswith(".log")
        #                and "combined" not in fname
        #                and not fname.startswith("benchmark_ips_artifact")
        #            ):
        #                path = os.path.join(log_dir, fname)
        #                try:
        #                    with open(path, "r") as infile:
        #                        outfile.write(f"===== {fname} =====\n")
        #                        outfile.write(infile.read() + "\n")
        #                except Exception as e:
        #                    patch7_logger.info(f"Skipped {fname}: {e}")
        #    patch7_logger.info(f"Combined runtime log written to: {combined_path}")
        #    return combined_path


        ## ------- Step 2:Create benchmark_path variable using runtime combiner -------
        ## The benchmark_path for example: /aws_EC2/logs/benchmark_combined_runtime.log
        #benchmark_path = combine_benchmark_logs_runtime(log_dir)



        ## ------- Step 3 + Step 4 -------
        ## The IP extractor uses this combined file in benchmark_patch to build the `benchmark_ips` set.
        ## Define the registry ip values: total, successful, failed and missing
        ## Total has Failed (explicit failures like watchdog retry threshold exceeded, etc) + successful
        ## Missing registry is the delta between benchmark_ips and total registry, i.e. those threads that are not caught by explicit
        ## failure detection logic.   Currently SSH failures, either in initializaton or failed 5 SSH retries need to be tagged as 
        ##failures OR untagged registry values NOT included in total registry so that they show up in missing registry
        ## Failed + Successful + Missing = total + missing = benchmark_ips

        #try:
        #    with open(benchmark_path, "r") as f:
        #        lines = f.readlines()
        #        patch7_logger.info(f"[Patch7] Runtime log line count: {len(lines)}")
        #        patch7_logger.info(f"[Patch7] Sample lines: {lines[:5]}")

        #        # 🔍 Block 1: Diagnostic check for presence of 'Public IP:'
        #        if any("Public IP:" in line for line in lines):
        #            patch7_logger.info("[Patch7] ✅ Found at least one line with Public IP")
        #        else:
        #            patch7_logger.warning("[Patch7] ❌ No Public IP lines found in runtime log")

        #        # 🔍 NEW Block: dump all candidate lines that contain "Public IP:"
        #        public_ip_lines = [line for line in lines if "Public IP:" in line]
        #        patch7_logger.info(f"[Patch7] 🔎 Lines with 'Public IP:': {public_ip_lines[:3]}")


        #        for i, line in enumerate(lines):
        #            if "Public IP:" in line:
        #                patch7_logger.info(f"[Patch7] 🧪 Raw candidate line {i}: {repr(line)}")
        #                
        #                ip_matches = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        #                if ip_matches:
        #                    patch7_logger.info(f"[Patch7] 🔥 Line {i}: Matched IPs: {ip_matches}")
        #                else:
        #                    patch7_logger.warning(f"[Patch7] ⚠️ Line {i} has 'Public IP:' but no regex match: {line.strip()}")

        #        # ⚙️ Comprehension that hydrates benchmark_ips
        #        benchmark_ips = {
        #            match.group(1)
        #            for line in lines
        #            #if (match := re.search(r"Public IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", line))
        #            if (match := re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line))
        #        }
        #        patch7_logger.info(f"[Patch7] 💧 Hydrated IPs: {benchmark_ips}")


        #    
        #    # the above is using uuid as key. Need ips. Use this:
        #    total_registry_ips = {
        #        entry.get("public_ip")
        #        for entry in process_registry.values()
        #        if entry.get("public_ip") is not None
        #    }




        #    ## Add these to troublehsoot artifact loggin issues. These go to the patch summary logs in the artifacts of gitlab piepline

        #    patch7_logger.info(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
        #    patch7_logger.info(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")
        #    patch7_logger.info(f"[Patch7] Sample benchmark IPs: {sorted(list(benchmark_ips))[:3]}")
        #    patch7_logger.info(f"[Patch7] Sample registry IPs: {sorted(list(total_registry_ips))[:3]}")
        #    # add these for gitlab console
        #    print(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
        #    print(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")



        #    # Debugs to ensure that the registry is intact from install_tomcat() which looks ok, to the resurrection_monitor() call
        #    # Replace resurrection_registry with process_registry in for loop for patch7c
        #    print(f"[RESMON DEBUG] Resurrection registry snapshot:")
        #    for ip, entry in process_registry.items():
        #        print(f"    {ip}: {entry}")
        #    
        #    # replace resurrection_registry with process_registry below
        #    #successful_registry_ips = {   #this returns uuids and not ips!!
        #    #    ip for ip, entry in process_registry.items()
        #    #    if entry.get("status") == "install_success"
        #    #    and entry.get("watchdog_retries", 0) <= 2
        #    #}


        #    # this will get the public ips and not uuids which is what we want
        #    successful_registry_ips = {
        #        entry.get("public_ip")
        #        for entry in process_registry.values()
        #        if entry.get("status") == "install_success"
        #        and entry.get("watchdog_retries", 0) <= 2
        #        and entry.get("public_ip") is not None
        #    }


        #    # Debugs to tell  how many IPs the above filter pulled through — and what the filter did to the full registry snapshot.
        #    print(f"[RESMON DEBUG] Registry IPs classified as successful: {successful_registry_ips}")



        #    failed_registry_ips = total_registry_ips - successful_registry_ips

        #    missing_registry_ips = benchmark_ips - total_registry_ips




        #    # Dump artifacts
        #    def dump_set_to_artifact(name, ip_set):
        #        path = os.path.join(log_dir, f"{name}_artifact.log")
        #        with open(path, "w") as f:
        #            for ip in sorted(ip_set):
        #                f.write(ip + "\n")
        #        patch7_logger.info(f"[Artifact Dump] {name}: {len(ip_set)} IPs dumped to {path}")

        #    def safe_artifact_dump(tag, ip_set):
        #        try:
        #            dump_set_to_artifact(tag, ip_set)
        #            patch7_logger.info(f"[Patch7] Artifact '{tag}' written with {len(ip_set)} entries.")
        #        except Exception as e:
        #            patch7_logger.info(f"[Patch7] Failed to write '{tag}': {e}")
        #   

        #    ## coment out the total, missing and the successful and the failed as these are done in main() now at the aggregated and not 
        #    ## the process level. benchmark_ips_artifact.log is the GOLD standard used by main(). So keep this one. Remove the other ones 
        #    ## from here.


        #    #if not total_registry_ips:
        #    #    patch7_logger.info("[Patch7] WARNING: total_registry_ips is empty — skipping artifact.")   
        #    #else:
        #    #     safe_artifact_dump("total_registry_ips", total_registry_ips)
        #  
        #    if not benchmark_ips:
        #        patch7_logger.info("[Patch7] WARNING: benchmark_ips is empty — skipping artifact.")
        #    else:
        #        safe_artifact_dump("benchmark_ips", benchmark_ips)
        #  
        #    #if not missing_registry_ips:
        #    #    patch7_logger.info("[Patch7] WARNING: missing_registry_ips is empty — skipping artifact.")
        #    #else:
        #    #    safe_artifact_dump("missing_registry_ips", missing_registry_ips)
        #  
        #    #if not successful_registry_ips:
        #    #    patch7_logger.info("[Patch7] WARNING: successful_registry_ips is empty — skipping artifact.")
        #    #else:
        #    #    safe_artifact_dump("successful_registry_ips", successful_registry_ips)
        #  
        #    #if not failed_registry_ips:
        #    #    patch7_logger.info("[Patch7] WARNING: failed_registry_ips is empty — skipping artifact.")
        #    #else:
        #    #    safe_artifact_dump("failed_registry_ips", failed_registry_ips)




        #    #dump_set_to_artifact("total_registry_ips", total_registry_ips)
        #    #dump_set_to_artifact("benchmark_ips", benchmark_ips)
        #    #dump_set_to_artifact("missing_registry_ips", missing_registry_ips)
        #    #dump_set_to_artifact("successful_registry_ips", successful_registry_ips)
        #    #dump_set_to_artifact("failed_registry_ips", failed_registry_ips)

        #    # Flag ghosts
        #    for ip in missing_registry_ips:
        #        flagged[ip] = {
        #            "status": "ghost_missing_registry",
        #            "ghost_reason": "no resurrection registry entry",
        #            "pid": pid,
        #            "timestamp": time.time()
        #        }
        #        log_debug(f"[{timestamp()}] Ghost flagged (missing registry): {ip}")



#### End of comment out of old benchmark_ips code ####


       




        try:

            # Flush the logger handlers to ensure all logs are written right before thread exit and summary conclusion
            for handler in patch7_logger.handlers:
                handler.flush()
            patch7_logger.info("🔄 Patch7 logger flushed successfully.")


            # Summary conclusion: This block will be used with patch 7d2 for process level stats .
            #Patch7_logger.info("🧪 Patch7 reached summary block execution.")
            #Patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
            #Patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
            #Patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
            #Patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
            #Patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
            #Patch7_logger.info(f"Composite alignment passed? {len(missing_registry_ips) + len(total_registry_ips) == len(benchmark_ips)}")
            

        # try block indentation level is here.

        except Exception as e:
            patch7_logger.error(f"Patch7 exception encountered: {e}")
            patch7_logger.error("Patch7 thread likely aborted before reaching summary block.")
            log_debug(f"[{timestamp()}] Patch7 failure: {e}")






# --- UPDATED RESURRECTION CANDIDATE JSON AND GHOST JSON PER PROCESS CODE. THIS REPLACED THE PATCH4 BLOCK ABOVE ---
# PID_JSON_DUMPS is an env variable used by gitlab .gitlab-ci.yml file to turn this on and off if it creates too much
# overhead during debugging hyper-scaling cases (where there can be a large number of registry threads in a failed, not successful
# state, and/or ghost threads

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")




# 🔒 Legacy ghost/candidate dump logic disabled — replaced by detect_ghosts() in Patch7d2
# Commented out to prevent redundant artifact writes and confusion during modular refactor

    ## only dump non-empty lists to avoid churn
    #if os.getenv("PID_JSON_DUMPS", "true").lower() in ("1","true"):
    #    # 1. Build your two lists
    #    candidates = [
    #        entry for entry in process_registry.values()
    #        if entry.get("status") != "install_success"
    #    ]
    #    seen_ips   = {e["public_ip"] for e in process_registry.values()}
    #    # benchmark_ips is already hydrated above by Patch7 logic
    #    ghosts     = sorted(benchmark_ips - seen_ips)

    #    # 2. Define file paths. These have replaced the legacy paths defined earlier.
    #    cand_file  = os.path.join(
    #        log_dir,
    #        f"resurrection_candidates_registry_{pid}_{ts}.json"
    #    )
    #    ghost_file = os.path.join(
    #        log_dir,
    #        f"resurrection_ghost_missing_{pid}_{ts}.json"
    #    )

    #    # 3. Write only if there’s something to write
    #    if candidates:
    #        with open(cand_file, "w") as f:
    #            json.dump(candidates, f, indent=2)
    #        patch7_logger.info(f"[Patch7] Wrote {len(candidates)} candidates to {cand_file}")

    #    if ghosts:
    #        with open(ghost_file, "w") as f:
    #            json.dump(ghosts, f, indent=2)
    #        patch7_logger.info(f"[Patch7] Wrote {len(ghosts)} ghosts to {ghost_file}")





    # ✅ Print final status and resurrection monitor final verdict
    if len(flagged) == 1 and "early_exit" in flagged:
        print(f"⚠️ Resurrection Monitor: Early thread exit detected in process {pid}.")
    elif flagged:
        print(f"🔍 Resurrection Monitor: {len(flagged)} thread(s) flagged in process {pid}.")
    else:
        print(f"✅ Resurrection Monitor: No thread failures in process {pid}.")


## Add flush at the end of the resurrection_monitor to help facilitate the logging to gitlab console configured above in patch7.
    sys.stdout.flush()


########## THIS IS THE END OF THE resurrection_monitor_patch8() function  ######################








###### COMMENT OUT THE ENTIRE OLD resurrection_monitor_patch7d. It is replaced with patch8 above ######


### REVISION 5: resurrection_monitor_patch7d
#
#
### Patch7d is below. This is to fix the ghost and candidate resurrection tagging and the json logging for both
### NOTE that this is per process level tagging and logging of the threads for ghosts and candidates
### main() does the logging for these at the aggregate level (for all processes) and that's working fine.
#
#
#
#
## ------------------ PATCH7C: THREAD-LOCAL RESURRECTION MONITOR ------------------
## Goal:   Create isolated thread-level logs for postmortem analysis and retry heuristics.
## Scope:  Operates on per-process registry (process_registry) assembled via tomcat_worker()
## Output: resurrection_registry_log_{pid}.json scoped to thread-local attempts
## -------------------------------------------------------------------------------
## Design note: Built atop Patch7b with scoped overrides to preserve thread-local logging clarity.
#
## === PATCH7C === Resurrection Monitor: Thread-Local Aggregation
##def resurrection_monitor_patch7c(log_dir="/aws_EC2/logs"):
## resurrection_monitor_patch7c needs to accept process_registry from tomcat_worker() now for patch7c
## process_registry has all IPs for multi-threaded process
## replace all resurrection_registry calls with process_registry BUT only in resurrection_monitor_patch7c function that gets
## the process_registry from the run_test call to threaded_install. The other resurrection_montior are global and are not
## to be changed.
#
#
#
#
#
######### patch7d1 ##########
##For patch7d we need to pass the instance_info from the higher level functions (tomcat_worker and tomcat_worker_wrapper) to
##the resurrection_monitor. instance_info is derived from tomcat_worker_wrapper which is called from main with the 
##  args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks] . This chunk is the chunk of ips that is 
## assigned to the pariticular process that will be run.  
#
## In main(), The chunk is derived from the instance_ips and the parameters as shown below:
## chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
## and this enumeration: for i, chunk in enumerate(chunks):   
## along with the args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks] 
## The arg list with chunk is passed to tomcat_worker_wrapper as `instance_info` : 
## `def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers)`
#
## main uses this function call to tomcat_worker_wrapper using the args_list above:
## `with multiprocessing.Pool(processes=desired_count) as pool:`
##            'pool.starmap(tomcat_worker_wrapper, args_list)`
#
## each process receives a `chunk` of IPs via `instance_info`, and that chunk is the authoritative list of IPs that the  process
## is responsible for. This is the  per-process GOLD standard analagous to the benchmark_ips at the aggregate level 
## (benchmark_ips_artifact.log)
#
## assigned_ips are the actual chunk ips assigned to this process, i.e. chunk or instance_info
## These are passed from the calling function tomcat_worker to resurrection_monitor_patch7d(process_registry, instance_info)
## THus instance_info is assigned_ips within this function
#############################
#
#
######### patch 7d2 ##########
#
## modularize and restructure the resurrection_monitor as it has a lot of old legacy code to be cleaned out and it also
## needs to be more organized. Will start with the hydrate_benchmark_ips() and the detect_ghosts() helper functions (global
## at the top of this python module. After that will continue to modularize the function as a lead in to patch8 which will
## code in the the definitive tags(statuses) of the registry values, both defining them and tagging the registries if
## they fail.   For patch 7d the logs will be noded as [RESMON_7d] for troubleshooting.
## A lot of the legacy code will be commented out or removed.
#############################
#
#
##def resurrection_monitor_patch7d(process_registry, log_dir="/aws_EC2/logs"):
#def resurrection_monitor_patch7d(process_registry, assigned_ips, log_dir="/aws_EC2/logs"):
#
#
#    pid = multiprocessing.current_process().pid
#
#    # add timestamp so that if pid is reused (as with hyper-scaling or pooling) the log files can be differentiated for 
#    # same pid with timestamp in the log file name.
#    # stamp each run so PIDs don’t collide
#    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
#
#
#
#    # This is the thread_id of the calling thread, and not the thread_ids of the worker threads (That are processing the ip addreses
#    # in the chunk_size
#    # Since resurrection_monitor_patch7c() is called at the end of tomcat_worker(), which runs in the main thread of the process, this line will return that main thread’s ID
#    # This will give us traceability if the thread diagnostics are expanded later on.
#
#    thread_id = threading.get_ident()
#
#    def log_debug(message):
#        print(message)
#
#    def timestamp():
#        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
#
#    ## These are the resurrection_registry patch 1-5 logs. These are tagged resurrection candidates for Phase3 implementation
#    #log_path = os.path.join(log_dir, f"resurrection_registry_log_{pid}.json")
#    # These logs will only be created if there are not successful registry entries in the process (to reduce artifact logging 
#    # overhead of blank json files. Note at global level we will create the json/log file regardless as it is only 1 file each for
#    # the entire execution.
#
#    #log_path = os.path.join(log_dir, f"resurrection_candidates_registry_{pid}.json")
#    # that new path for this  is defined in the new code block at the bottom of this function 
#
#
#    ## These are teh resurrection ghost patch 7 logs. These are missing registry entires that are in benchmark_ips but are not in the
#    ## the registry (missing = benchmark - total registry)
#    #ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_log_{pid}.json")
#    # This json will only be created if there are ghosts in the process
#
#    #ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}.json")
#    # the new path for this is defined in the new code block at the bottom of this function 
#
#
#
#    ### This log is now created in main() as part of the aggregation in main()
#    ## This is the full snapshot of the registry (all of them: success and fail) per process as part of phase7c
#    ## This is multi-threaded and will have all the registry IPs that are being processed by the process (chunk_size number of IPs)
#    ## for max_workers threads
#    #These is no need to create a process level registry json file for all the processes. It will create a large amount of overhead
#    #in terms of artifact files.
#
#    #full_process_snapshot_path = os.path.join(log_dir, f"resurrection_process_registry_snapshot_{pid}.json")
#
#
#    # Patch 7d2 move this block from the old code for the benchmark_combined_runtime.log generation
#    # ------- Combine runtime benchmark logs: filtered for benchmark_combined_runtime.log  -------
#    #merged contents from all `benchmark_*.log` PID logs that were created at runtime
#    def combine_benchmark_logs_runtime(log_dir, patch7_logger):
#        benchmark_combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
#        with open(benchmark_combined_path, "w") as outfile:
#            for fname in sorted(os.listdir(log_dir)):
#                # Only combine true benchmark logs — exclude artifact and combined logs
#                if (
#                    fname.startswith("benchmark_")
#                    and fname.endswith(".log")
#                    and "combined" not in fname
#                    and not fname.startswith("benchmark_ips_artifact")
#                ):
#                    path = os.path.join(log_dir, fname)
#                    try:
#                        with open(path, "r") as infile:
#                            outfile.write(f"===== {fname} =====\n")
#                            outfile.write(infile.read() + "\n")
#                    except Exception as e:
#                        patch7_logger.info(f"Skipped {fname}: {e}")
#        patch7_logger.info(f"Combined runtime log written to: {benchmark_combined_path}")
#        return benchmark_combined_path
#
#
#
#
#
#
#
#
#
#
### With patch7d2 the resurrection_registry_lock is no longer required:
###- **`process_registry` is per-process and local** — no shared memory, no race conditions.
###- **`resurrection_registry_lock` was originally protecting shared writes** to a global registry or artifact store, but
### these are now being modularized.
###- **Ghost detection and benchmark hydration are read-only operations** — they don’t mutate shared state, so locking is 
###unnecessary.
#
#
#
#    flagged = {}
#    with resurrection_registry_lock:
#        
#
#
#
#
#
#
#
#
#        # Patch5: This sets the stage for patches 5 and 6.  We are creating total_registry_ips for all ips in registry
#        # (i.e. watchdogs that exceeded threshold, our unknown signature ghost, successful fingerprinted ones in install_tomcat,
#        # i.e., patch1)
#        # and also creating successful_registry_ips (the fingerprinted ones in install_tomcat, i.e. patch1)
#        # The objective is with patch 6 and 7 to identify the unknown ghosts in total_registry_ips and then
#        # total_registry_ips -(successful_registry_ips) = our elusive ghost threads
#        # These ghost threads are threads that have bypassed all conditions so far in the resurrection_gatekeeper and the
#        # read_output_with_watchdog functions:
#        # - They exited before hitting the stall threshold (`read_output_with_watchdog`)
#        #- They bypassed resurrection gatekeeper entirely
#        #- No fingerprint means no resurrection log
#
#
##        total_registry_ips = set(resurrection_registry.keys())
##        successful_registry_ips = {
##            ip for ip, record in resurrection_registry.items()
##            if record.get("status") == "install_success"
##        }
##
### Replace resurrection_registry with the process_registry for only def resurrection_monitor_patch7c, from threaded_install()
#        
#
#       
#
#       # total_registry_ips = set(process_registry.keys()) # process_registry.keys returns uuid and not ip!!
#       # successful_registry_ips = {
#       #     ip for ip, record in process_registry.items()
#       #     if record.get("status") == "install_success"
#       # }
#
#        # this syntax returns ips and not uuids. This is what we want.
#        total_registry_ips = {
#            entry.get("public_ip")
#            for entry in process_registry.values()
#            if entry.get("public_ip") is not None
#        }
#
#        successful_registry_ips = {
#            entry.get("public_ip")
#            for entry in process_registry.values()
#            if entry.get("status") == "install_success"
#        }
#
#
#
#        # ---------------- Begin Resurrection Registry Scan (patches 2 and 5) ----------------
#        
#        
#
#        ## We are now keying on thread_uuid. Keying on ip is causing problems. This is a small change as indicated below.
#
#        #for ip, record in process_registry.items():
#        #replace process_registry for resurrection_registry for patch7c    
#        #for ip, record in resurrection_registry.items():
#        
#        for thread_uuid, record in process_registry.items():
#            ip = record.get("public_ip")
#            if not ip:
#                continue  # Skip entries without a public IP
#
#
#            # 🛑 Skip nodes that completed successfully. This is patch2 to address this issue where we are
#            # seeing successful installations having resurrection logs created. Patch1, creating a registry
#            # fingerprint for successful installs at the end of install_tomcat() did not address this problem
#            # Patch1 is at the end of install_tomcat() with install_success fingerprint stamping.
#            if record.get("status") == "install_success":
#                continue
#
#
#            reason = "watchdog stall retry threshold" if "timeout" in record["status"] or record["attempt"] >= STALL_RETRY_THRESHOLD else "not in successful_registry_ips"
#            record["ghost_reason"] = reason
#            flagged[ip] = record
#            log_debug(f"[{timestamp()}] Ghost candidate flagged ({reason}): {ip}")
#
#
##            if "timeout" in record["status"] or record["attempt"] >= STALL_RETRY_THRESHOLD:
##                flagged[ip] = record
##                log_debug(f"[{timestamp()}] Ghost candidate flagged (watchdog stall retry threshold): {ip}")  
##
##            if ip not in successful_registry_ips:
##                # 👻 Potential ghost thread detected
##                flagged[ip] = record
##                log_debug(f"[{timestamp()}] Ghost candidate flagged (in total_registry_ips): {ip}")
##                
#
#
#
######## UPDATED PATCH 7b to address cross log corruption  ################
#
##- Prevents `Patch7 Summary` lines from leaking into:
##- `benchmark_*.log` (PID logs)
##- `benchmark_combined.log` (CI-generated artifact log)
##-  Still generates `benchmark_combined_runtime.log` inside the container
##-  Writes artifact logs for registry analysis (`*_artifact.log`)
##-  Logs Patch7 summary to a **dedicated file**, not `stdout`
##-  Fully isolates `patch7_logger` so it never touches shared streams
##
#
#### Updated Patch7 Block 
#
#
#
#
#
#
#
#        # ------- Patch7 Logger Isolation -------
#        #This creates a **dedicated logger instance** for Patch7 inside the resurrection monitor, uniquely scoped to the process that’s
#        #running it.
#        #- The `f"patch7_summary_{pid}"` string makes sure each logger has a unique name per process (e.g., `"patch7_summary_12"`)
#        #- This ensures multiple processes don’t reuse or interfere with each other’s loggers — no cross-stream contamination
#        #- It allows each resurrection monitor instance to write its own Patch7 summary without touching any shared file or the global
#        #logger
#
#        patch7_logger = logging.getLogger(f"patch7_summary_{pid}")
#        patch7_logger.setLevel(logging.INFO)
#        patch7_logger.propagate = False  # ✋ Prevent root logger inheritance
#
#        # 🗂️ File-based log to avoid stdout interference
#
#        #- `log_dir` is mount target from `.gitlab-ci.yml`,  `/aws_EC2/logs` inside the docker container
#        #- `f"patch7_summary_{pid}.log"` gives files like `patch7_summary_12.log`, `patch7_summary_48.log`, etc.
#        #- All Patch7 messages will be written **only** to this file — no stdout, no collision with benchmark PID logs
#        #This is what enables the safe write
#
#        # summary_handler:
#        # Attaches a file-based handler to the logger — meaning all `patch7_logger.info(...)` calls write directly to the file at
#        #`summary_log_path`.
#        #- This avoids `StreamHandler(sys.stdout)`, which is the usual culprit for GitLab log bleed
#        #- It ensures everything written is scoped to one file — line-by-line controlled output
#
#        #summary_log_path = os.path.join(log_dir, f"patch7_summary_{pid}.log")
#        # use ts (timestamp) to avoid issues with pid reuse that occurs with hyper-scaling and pooling
#        summary_log_path = os.path.join(
#          log_dir, f"patch7_summary_{pid}_{ts}.log"
#         )
#
#
#        # Use write mode use mode="w" to overwrite any existing file of the same name (this is for pid reuse case if files are 
#        # named the same. This should not happen any longer because timestamp is now added to log filename along with pid)
#        #summary_handler = logging.FileHandler(summary_log_path)
#        summary_handler = logging.FileHandler(summary_log_path, mode="w")
#
#        summary_formatter = logging.Formatter('[Patch7] %(message)s')
#        summary_handler.setFormatter(summary_formatter)
#        patch7_logger.addHandler(summary_handler)
#
#        patch7_logger.info("Patch7 Summary — initialized")
#
#
#
#
#
#
#
#        ###### for patch7d2 modularization. Move all of this stuff after the patch7_logger is defined ########
#        
#        # this will create the benchmark_combined_runtime.log from which we can hydrate benchmark_ips
#        benchmark_combined_path = combine_benchmark_logs_runtime(log_dir, patch7_logger)
#
#
#        ## Patch 7d2 modularization patch changes:
#        ## Frist call to hydrate_benchmark_ips global helper function to derive the benchmark_ips GOLD standard thread/ip list that
#        ## is required for ghost detection in main() at the aggregate level
#        ## Large blocks of the old code for this need to be commented out below. These will be noted with 7d2 in the comments.
#
#
#        benchmark_ips = hydrate_benchmark_ips(log_dir)
#
#        ## print the artifact that is derived from benchmark_ips,the benchmark_ips_artifact.log that is the runtime list of all
#        ## the IPs/theads in the execution run.This is exported out to the gitlab pipeline
#
#        with open(os.path.join(log_dir, "benchmark_ips_artifact.log"), "w") as f:
#            for ip in sorted(benchmark_ips):
#                f.write(ip + "\n")
#
#
#        ##  Move this block to here. This will be replaced by the detect_ghosts() helper function.
#
#        ####################
#        ## insert patch7d fixes:
#        ## This is early code for testing the refactor for ghost detection for 7d2 modularization. This is working well.
#        # Extract seen IPs from the current process registry
#        seen_ips = {entry["public_ip"] for entry in process_registry.values() if entry.get("public_ip")}
#        # Build assigned IPs set from the chunk passed to this process
#        assigned_ip_set = {ip["PublicIpAddress"] for ip in assigned_ips}
#        # Detect ghosts — IPs assigned to this process but missing from registry
#        ghosts = sorted(assigned_ip_set - seen_ips)
#        
#        # log to console 
#        for ip in ghosts:
#            print(f"[Patch7d] 👻 Ghost detected in process {pid}: {ip}")
#
#        # log to the artifacts in gitlab
#        if ghosts:
#            ghost_file = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}_{ts}.json")
#            with open(ghost_file, "w") as f:
#                json.dump(ghosts, f, indent=2)
#         ####################
#
#
#
#
#
###### Begin comment out of old benchmark_ips  code.
###### This is the old benchmark_ips generation code.This has been replaced by the global modular function above
###### as part of patch 7d2, hydrate_benchmark_ips()
###### All of this code needs to be commented out after adding the call to hydrate_benchmark_ips early in the 
###### res mon function (see above)
#
#
#        ## ------- Step 1: Combine runtime benchmark logs: filtered -------
#        ##merged contents from all `benchmark_*.log` PID logs that were created at runtime
#        #def combine_benchmark_logs_runtime(log_dir):
#        #    combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
#        #    with open(combined_path, "w") as outfile:
#        #        for fname in sorted(os.listdir(log_dir)):
#        #            # Only combine true benchmark logs — exclude artifact and combined logs
#        #            if (
#        #                fname.startswith("benchmark_")
#        #                and fname.endswith(".log")
#        #                and "combined" not in fname
#        #                and not fname.startswith("benchmark_ips_artifact")
#        #            ):
#        #                path = os.path.join(log_dir, fname)
#        #                try:
#        #                    with open(path, "r") as infile:
#        #                        outfile.write(f"===== {fname} =====\n")
#        #                        outfile.write(infile.read() + "\n")
#        #                except Exception as e:
#        #                    patch7_logger.info(f"Skipped {fname}: {e}")
#        #    patch7_logger.info(f"Combined runtime log written to: {combined_path}")
#        #    return combined_path
#
#
#        ## ------- Step 2:Create benchmark_path variable using runtime combiner -------
#        ## The benchmark_path for example: /aws_EC2/logs/benchmark_combined_runtime.log
#        #benchmark_path = combine_benchmark_logs_runtime(log_dir)
#
#
#
#        ## ------- Step 3 + Step 4 -------
#        ## The IP extractor uses this combined file in benchmark_patch to build the `benchmark_ips` set.
#        ## Define the registry ip values: total, successful, failed and missing
#        ## Total has Failed (explicit failures like watchdog retry threshold exceeded, etc) + successful
#        ## Missing registry is the delta between benchmark_ips and total registry, i.e. those threads that are not caught by explicit
#        ## failure detection logic.   Currently SSH failures, either in initializaton or failed 5 SSH retries need to be tagged as 
#        ##failures OR untagged registry values NOT included in total registry so that they show up in missing registry
#        ## Failed + Successful + Missing = total + missing = benchmark_ips
#
#        #try:
#        #    with open(benchmark_path, "r") as f:
#        #        lines = f.readlines()
#        #        patch7_logger.info(f"[Patch7] Runtime log line count: {len(lines)}")
#        #        patch7_logger.info(f"[Patch7] Sample lines: {lines[:5]}")
#
#        #        # 🔍 Block 1: Diagnostic check for presence of 'Public IP:'
#        #        if any("Public IP:" in line for line in lines):
#        #            patch7_logger.info("[Patch7] ✅ Found at least one line with Public IP")
#        #        else:
#        #            patch7_logger.warning("[Patch7] ❌ No Public IP lines found in runtime log")
#
#        #        # 🔍 NEW Block: dump all candidate lines that contain "Public IP:"
#        #        public_ip_lines = [line for line in lines if "Public IP:" in line]
#        #        patch7_logger.info(f"[Patch7] 🔎 Lines with 'Public IP:': {public_ip_lines[:3]}")
#
#
#        #        for i, line in enumerate(lines):
#        #            if "Public IP:" in line:
#        #                patch7_logger.info(f"[Patch7] 🧪 Raw candidate line {i}: {repr(line)}")
#        #                
#        #                ip_matches = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
#        #                if ip_matches:
#        #                    patch7_logger.info(f"[Patch7] 🔥 Line {i}: Matched IPs: {ip_matches}")
#        #                else:
#        #                    patch7_logger.warning(f"[Patch7] ⚠️ Line {i} has 'Public IP:' but no regex match: {line.strip()}")
#
#        #        # ⚙️ Comprehension that hydrates benchmark_ips
#        #        benchmark_ips = {
#        #            match.group(1)
#        #            for line in lines
#        #            #if (match := re.search(r"Public IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", line))
#        #            if (match := re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line))
#        #        }
#        #        patch7_logger.info(f"[Patch7] 💧 Hydrated IPs: {benchmark_ips}")
#
#
#        #    
#        #    # the above is using uuid as key. Need ips. Use this:
#        #    total_registry_ips = {
#        #        entry.get("public_ip")
#        #        for entry in process_registry.values()
#        #        if entry.get("public_ip") is not None
#        #    }
#
#
#
#
#        #    ## Add these to troublehsoot artifact loggin issues. These go to the patch summary logs in the artifacts of gitlab piepline
#
#        #    patch7_logger.info(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
#        #    patch7_logger.info(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")
#        #    patch7_logger.info(f"[Patch7] Sample benchmark IPs: {sorted(list(benchmark_ips))[:3]}")
#        #    patch7_logger.info(f"[Patch7] Sample registry IPs: {sorted(list(total_registry_ips))[:3]}")
#        #    # add these for gitlab console
#        #    print(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
#        #    print(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")
#
#
#
#        #    # Debugs to ensure that the registry is intact from install_tomcat() which looks ok, to the resurrection_monitor() call
#        #    # Replace resurrection_registry with process_registry in for loop for patch7c
#        #    print(f"[RESMON DEBUG] Resurrection registry snapshot:")
#        #    for ip, entry in process_registry.items():
#        #        print(f"    {ip}: {entry}")
#        #    
#        #    # replace resurrection_registry with process_registry below
#        #    #successful_registry_ips = {   #this returns uuids and not ips!!
#        #    #    ip for ip, entry in process_registry.items()
#        #    #    if entry.get("status") == "install_success"
#        #    #    and entry.get("watchdog_retries", 0) <= 2
#        #    #}
#
#
#        #    # this will get the public ips and not uuids which is what we want
#        #    successful_registry_ips = {
#        #        entry.get("public_ip")
#        #        for entry in process_registry.values()
#        #        if entry.get("status") == "install_success"
#        #        and entry.get("watchdog_retries", 0) <= 2
#        #        and entry.get("public_ip") is not None
#        #    }
#
#
#        #    # Debugs to tell  how many IPs the above filter pulled through — and what the filter did to the full registry snapshot.
#        #    print(f"[RESMON DEBUG] Registry IPs classified as successful: {successful_registry_ips}")
#
#
#
#        #    failed_registry_ips = total_registry_ips - successful_registry_ips
#
#        #    missing_registry_ips = benchmark_ips - total_registry_ips
#
#
#
#
#        #    # Dump artifacts
#        #    def dump_set_to_artifact(name, ip_set):
#        #        path = os.path.join(log_dir, f"{name}_artifact.log")
#        #        with open(path, "w") as f:
#        #            for ip in sorted(ip_set):
#        #                f.write(ip + "\n")
#        #        patch7_logger.info(f"[Artifact Dump] {name}: {len(ip_set)} IPs dumped to {path}")
#
#        #    def safe_artifact_dump(tag, ip_set):
#        #        try:
#        #            dump_set_to_artifact(tag, ip_set)
#        #            patch7_logger.info(f"[Patch7] Artifact '{tag}' written with {len(ip_set)} entries.")
#        #        except Exception as e:
#        #            patch7_logger.info(f"[Patch7] Failed to write '{tag}': {e}")
#        #   
#
#        #    ## coment out the total, missing and the successful and the failed as these are done in main() now at the aggregated and not 
#        #    ## the process level. benchmark_ips_artifact.log is the GOLD standard used by main(). So keep this one. Remove the other ones 
#        #    ## from here.
#
#
#        #    #if not total_registry_ips:
#        #    #    patch7_logger.info("[Patch7] WARNING: total_registry_ips is empty — skipping artifact.")   
#        #    #else:
#        #    #     safe_artifact_dump("total_registry_ips", total_registry_ips)
#        #  
#        #    if not benchmark_ips:
#        #        patch7_logger.info("[Patch7] WARNING: benchmark_ips is empty — skipping artifact.")
#        #    else:
#        #        safe_artifact_dump("benchmark_ips", benchmark_ips)
#        #  
#        #    #if not missing_registry_ips:
#        #    #    patch7_logger.info("[Patch7] WARNING: missing_registry_ips is empty — skipping artifact.")
#        #    #else:
#        #    #    safe_artifact_dump("missing_registry_ips", missing_registry_ips)
#        #  
#        #    #if not successful_registry_ips:
#        #    #    patch7_logger.info("[Patch7] WARNING: successful_registry_ips is empty — skipping artifact.")
#        #    #else:
#        #    #    safe_artifact_dump("successful_registry_ips", successful_registry_ips)
#        #  
#        #    #if not failed_registry_ips:
#        #    #    patch7_logger.info("[Patch7] WARNING: failed_registry_ips is empty — skipping artifact.")
#        #    #else:
#        #    #    safe_artifact_dump("failed_registry_ips", failed_registry_ips)
#
#
#
#
#        #    #dump_set_to_artifact("total_registry_ips", total_registry_ips)
#        #    #dump_set_to_artifact("benchmark_ips", benchmark_ips)
#        #    #dump_set_to_artifact("missing_registry_ips", missing_registry_ips)
#        #    #dump_set_to_artifact("successful_registry_ips", successful_registry_ips)
#        #    #dump_set_to_artifact("failed_registry_ips", failed_registry_ips)
#
#        #    # Flag ghosts
#        #    for ip in missing_registry_ips:
#        #        flagged[ip] = {
#        #            "status": "ghost_missing_registry",
#        #            "ghost_reason": "no resurrection registry entry",
#        #            "pid": pid,
#        #            "timestamp": time.time()
#        #        }
#        #        log_debug(f"[{timestamp()}] Ghost flagged (missing registry): {ip}")
#
#
#
##### End of comment out of old benchmark_ips code ####
#
#
#       
#
#
#
#
#        try:
#
#            # Flush the logger handlers to ensure all logs are written right before thread exit and summary conclusion
#            for handler in patch7_logger.handlers:
#                handler.flush()
#            patch7_logger.info("🔄 Patch7 logger flushed successfully.")
#
#
#            # Summary conclusion: This block will be used with patch 7d2 for process level stats .
#            #Patch7_logger.info("🧪 Patch7 reached summary block execution.")
#            #Patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
#            #Patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
#            #Patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
#            #Patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
#            #Patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
#            #Patch7_logger.info(f"Composite alignment passed? {len(missing_registry_ips) + len(total_registry_ips) == len(benchmark_ips)}")
#            
#
#        # try block indentation level is here.
#
#        except Exception as e:
#            patch7_logger.error(f"Patch7 exception encountered: {e}")
#            patch7_logger.error("Patch7 thread likely aborted before reaching summary block.")
#            log_debug(f"[{timestamp()}] Patch7 failure: {e}")
#
#
#
#
#
#
## --- UPDATED RESURRECTION CANDIDATE JSON AND GHOST JSON PER PROCESS CODE. THIS REPLACED THE PATCH4 BLOCK ABOVE ---
## PID_JSON_DUMPS is an env variable used by gitlab .gitlab-ci.yml file to turn this on and off if it creates too much
## overhead during debugging hyper-scaling cases (where there can be a large number of registry threads in a failed, not successful
## state, and/or ghost threads
#
#    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
#
#
#
#
## 🔒 Legacy ghost/candidate dump logic disabled — replaced by detect_ghosts() in Patch7d2
## Commented out to prevent redundant artifact writes and confusion during modular refactor
#
#    ## only dump non-empty lists to avoid churn
#    #if os.getenv("PID_JSON_DUMPS", "true").lower() in ("1","true"):
#    #    # 1. Build your two lists
#    #    candidates = [
#    #        entry for entry in process_registry.values()
#    #        if entry.get("status") != "install_success"
#    #    ]
#    #    seen_ips   = {e["public_ip"] for e in process_registry.values()}
#    #    # benchmark_ips is already hydrated above by Patch7 logic
#    #    ghosts     = sorted(benchmark_ips - seen_ips)
#
#    #    # 2. Define file paths. These have replaced the legacy paths defined earlier.
#    #    cand_file  = os.path.join(
#    #        log_dir,
#    #        f"resurrection_candidates_registry_{pid}_{ts}.json"
#    #    )
#    #    ghost_file = os.path.join(
#    #        log_dir,
#    #        f"resurrection_ghost_missing_{pid}_{ts}.json"
#    #    )
#
#    #    # 3. Write only if there’s something to write
#    #    if candidates:
#    #        with open(cand_file, "w") as f:
#    #            json.dump(candidates, f, indent=2)
#    #        patch7_logger.info(f"[Patch7] Wrote {len(candidates)} candidates to {cand_file}")
#
#    #    if ghosts:
#    #        with open(ghost_file, "w") as f:
#    #            json.dump(ghosts, f, indent=2)
#    #        patch7_logger.info(f"[Patch7] Wrote {len(ghosts)} ghosts to {ghost_file}")
#
#
#
#
#
#    # ✅ Print final status and resurrection monitor final verdict
#    if len(flagged) == 1 and "early_exit" in flagged:
#        print(f"⚠️ Resurrection Monitor: Early thread exit detected in process {pid}.")
#    elif flagged:
#        print(f"🔍 Resurrection Monitor: {len(flagged)} thread(s) flagged in process {pid}.")
#    else:
#        print(f"✅ Resurrection Monitor: No thread failures in process {pid}.")
#
#
### Add flush at the end of the resurrection_monitor to help facilitate the logging to gitlab console configured above in patch7.
#    sys.stdout.flush()
#
#
########### THIS IS THE END OF THE resurrection_monitor_patch7d() function  ######################
#



#### As part of patch8 delete the older REVISIONS 4(patch7c),3,2,and 1 from the comments as part of the cleanup to the code #####











# ------------------ RESURRECTION REGISTRY + WATCHDOG HOOKS ------------------
# Purpose: Detect stalled STDOUT/STDERR reads during SSH execution inside install_tomcat()
#          and flag repeated failures for postmortem analysis or thread resurrection.
# Scope:   Shared across all threads and processes launched from tomcat_worker()
# Output:  Structured JSON log via resurrection_monitor() at end of each process lifecycle
# ---------------------------------------------------------------------------


# move this stuff to top of module
#from datetime import datetime
#import threading
#
#WATCHDOG_TIMEOUT = 90
#RETRY_LIMIT = 3
#SLEEP_BETWEEN_ATTEMPTS = 5
#STALL_RETRY_THRESHOLD = 2





resurrection_registry = {}
resurrection_registry_lock = threading.Lock()

# As part of phase2, add pid to the update_resurrection_registry for patch 6 fix and make sure to add pid=multiprocessing.current_process().pid to all the function call arguments using this function

def update_resurrection_registry(ip, attempt, status, pid=None):
    print(f"[TRACE][res_registry] Updating registry for {ip} with PID {pid}")
    with resurrection_registry_lock:
        resurrection_registry[ip] = {
            "status": status,
            "attempt": attempt,
            "timestamp": datetime.now().isoformat(),
            "pid": pid
        }
    print(f"[TRACE][res_registry] Finished registry update for {ip}")    




#def read_output_with_watchdog(stream, label, ip, attempt):
#    start = time.time()
#    collected = b''
#    while True:
#        if stream.channel.recv_ready():
#            try:
#                collected += stream.read()
#                break
#            except Exception as e:
#                print(f"[{ip}] ⚠️ Failed reading {label} (Attempt {attempt}): {e}")
#                break
#
#        elapsed = time.time() - start
#        if elapsed > WATCHDOG_TIMEOUT:
#            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read (Attempt {attempt}).")
#            if attempt >= STALL_RETRY_THRESHOLD:
#                print(f"[{ip}] 🔄 Multiple stalls detected. Flagging for resurrection.")
#                update_resurrection_registry(ip, attempt, f"watchdog_timeout_on_{label}", pid=multiprocessing.current_process().pid)
#            break # break out if stall retry threshold is reached and return to install_tomcat. We will create a stub
#        # registry entry for this case in install_tomcat upon the break return.
#        time.sleep(1)
#    return collected.decode()
#





## updated and refactored read_output_with_watchdog. Remove attempt and add a local counter for detecting watchdog 
## threshold. Add logic to wait for the output to threads to flush late before declaring a stub
## check both STDOUT and STDERR for zero and must be stalled as well.
##- `stalled` is only `True` if:
##  - The stall threshold was hit **and**
##  - The decoded output is empty (i.e. `not output.strip()`)

#def read_output_with_watchdog(stream, label, ip):
#    stall_count = 0
#    collected = b''
#    start = time.time()
#
#    while True:
#        if stream.channel.recv_ready():
#            try:
#                collected += stream.read()
#                break
#            except Exception as e:
#                print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
#                break
#
#        elapsed = time.time() - start
#        if elapsed > WATCHDOG_TIMEOUT:
#            stall_count += 1
#            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read. Stall count: {stall_count}")
#            if stall_count >= STALL_RETRY_THRESHOLD:
#                print(f"[{ip}] 🔄 Stall threshold exceeded on {label}.")
#                break  # Don't return early — let output flush after break
#            start = time.time()
#
#        time.sleep(1)
#
#    output = collected.decode()
#    stalled = stall_count >= STALL_RETRY_THRESHOLD and not output.strip()
#    return output, stalled






## further optimizations on the waiting for the output to flush from the node. Introduced the grace window.
## The purpose of the watchdog at the thread level is to detect thread output data flush starvation and give the
## thread enough time to collect STDOUT and STDERR for further analysis by install_tomcat (failure/stub detection)
## The stalled indicator below is not used, but is left in for possible future use.  The watchdog in read_output_with_watchdog
## is NOT used for failure detection. Failure detection is done solely based upon the stream detection done in 
## read_output_with_watchodg. Based upon the command semantics and output the decision on whether is is a falure, stub, 
## or success is done in install_tomcat logic based on STDOUT and STDERR of the output flush stream for that command.


# METHOD1: deprecated.   This is stream based:
#using Paramiko’s `stdout.readline()` or `stdout.channel.recv_ready()` logic. It’s:

#- **Line-oriented**: Reads one line at a time
#- **Dependent on channel readiness**: Relies on `recv_ready()` or `exit_status_ready()` to decide when to read
#- **Vulnerable to timing issues**: If the stream isn’t ready or flushes late, you get blank or partial output

# In testing it has been shown to be incosistent. There is also a buffer collision with reads done on the calling function
# from install_tomcat causing more issues.    Goding to switch to METHOD2 below using RAW.

#def read_output_with_watchdog(stream, label, ip):
#    stall_count = 0
#    collected = b''
#    start = time.time()
#
#    while True:
#        if stream.channel.recv_ready():
#            try:
#                collected += stream.read()
#                break
#            except Exception as e:
#                print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
#                break
#
#        elapsed = time.time() - start
#        if elapsed > WATCHDOG_TIMEOUT:
#            stall_count += 1
#            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read. Stall count: {stall_count}")
#            if stall_count >= STALL_RETRY_THRESHOLD:
#                print(f"[{ip}] 🔄 Stall threshold exceeded on {label}. Breaking loop.")
#                break  # Exit loop, but do final flush check below
#            start = time.time()
#
#        time.sleep(1)
#
#    ## Final flush attempt after stall threshold. This is the main modification.
#    #if stream.channel.recv_ready():
#    #    try:
#    #        collected += stream.read()
#    #        print(f"[{ip}] 📥 Final flush read succeeded on {label}.")
#    #    except Exception as e:
#    #        print(f"[{ip}] ⚠️ Final read failed after stall threshold on {label}: {e}")
#
#
#
#    # After breaking loop due to stall threshold
#    flush_deadline = time.time() + 10  # Grace window: 5 seconds
#    while time.time() < flush_deadline:
#        if stream.channel.recv_ready():
#            try:
#                chunk = stream.read()
#                collected += chunk
#                print(f"[{ip}] 📥 Post-loop flush read: {len(chunk)} bytes on {label}")
#                break  # Exit early if output arrives
#            except Exception as e:
#                print(f"[{ip}] ⚠️ Post-loop flush read failed on {label}: {e}")
#        time.sleep(0.5)
#
#    ## output limiting. There is no need to collect the entire output stream for purposes of command success or failure.
#    output = collected.decode(errors="ignore")
#    lines = output.strip().splitlines()
#    preview = "\n".join(lines[:3])
#    print(f"[{ip}] 🔍 Final output after flush (first {min(len(lines),3)} lines):\n{preview}")
#
#
#
#    # Get rid of this and replace with above. This is too verbose.  Need to limit gitlab console logs.  
#    #print(f"[{ip}] 🔍 Final output after flush: '{output.strip()}'")
#
#
#
#    # the key decision logic is below. The watchdog at this level is to detect thread starvation and not to decide
#    # failure, success or stub status (that is done in install_tomcat, the calling function)
#    # Logic below:
#    #This is the key line:
#    #- If we hit the stall threshold **and** the output is blank → `stalled = True`
#    #- If we hit the stall threshold **but** got some output → `stalled = False`
#    #- If we never hit the stall threshold → `stalled = False`
#
#    #Special case is commands that have no output. They will hit the watchdog attempts threshold and there will be no output 
#    #and it will be stalled =True but the logic in install_tomcat will prevent a stub or failed registry_entry due to command 
#    #attempt count of 1 (attempt=0) and an exit code of 0 (success). Stub and failed registry_entry in install_tomcat are gated.
#
#    stalled = stall_count >= STALL_RETRY_THRESHOLD and not output.strip()
#    return output, stalled
#
#    ## for now "stalled" is not used in the criteria for command success or failure. This logic has been moved to 
#    ## install_tomcat. The output stream is the primary artifact from read_output_with_watchdog that is used by
#    ## install_tomcat to decide on command success or failure. See install_tomcat, the calling function.
#



# METHOD2 for read_output_with_watchdog:
# raw  byte reads based on chunks of data (will use 4096) This will improve the consistentcy of the STDOUT and STDERR
# from the thread/command interation and at the same time we retain the watchdog and grace for late output flush 
# scenarios that can occur with certain commands.

# Advantages:
#- **Direct access to the stream buffer**: Using `stdout.read()` or `stdout.channel.recv(n)` to pull raw bytes
#- **Decoding after collection**: Decode once at the end, avoiding mid-stream decode errors
#- **Graceful fallback**: If output is delayed, the watchdog loop keeps polling until timeout or flush
#- channel_recv(n) is nonblocking unlike the stream baased stream.read above (METHOD1)

# The Result:
#- Fast capture for normal output
#- Resilient collection for laggards
#- Clean separation of concerns — no reads in `install_tomcat`, all logic centralized in the watchdog
# install_tomcat is soley for failure/stub/success logic based upon the flow STDOUT and STDERR returned from this function

#1. **Initialize a byte buffer**
#2. **Loop with timeout and grace**
#   - Use `channel.recv(n)` to read chunks
#   - Append to buffer
#   - Log byte count and preview
#3. **Decode once at the end**
#   - Handle decode errors gracefully
#   - Return decoded output and stall status



def read_output_with_watchdog(stream, label, ip):
    stall_count = 0
    collected = b''
    start = time.time()

    while True:
        if stream.channel.recv_ready():  # these are the key changes from METHOD1. This is RAW:
            try:
                chunk = stream.channel.recv(4096)
                collected += chunk
                print(f"[{ip}] 📥 Watchdog read: {len(chunk)} bytes on {label}")
                break  # Exit after first successful read
            except Exception as e:
                print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
                break

        elapsed = time.time() - start
        if elapsed > WATCHDOG_TIMEOUT:
            stall_count += 1
            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read. Stall count: {stall_count}")
            if stall_count >= STALL_RETRY_THRESHOLD:
                print(f"[{ip}] 🔄 Stall threshold exceeded on {label}. Breaking loop.")
                break
            start = time.time()

        time.sleep(1)

    # Post-loop grace flush
    flush_deadline = time.time() + 10  # Grace window
    while time.time() < flush_deadline:
        if stream.channel.recv_ready():
            try:
                chunk = stream.channel.recv(4096)
                collected += chunk
                print(f"[{ip}] 📥 Post-loop flush read: {len(chunk)} bytes on {label}")
                break
            except Exception as e:
                print(f"[{ip}] ⚠️ Post-loop flush read failed on {label}: {e}")
        time.sleep(0.5)

    # Decode and preview
    output = collected.decode(errors="ignore")
    lines = output.strip().splitlines()
    preview = "\n".join(lines[:3])
    print(f"[{ip}] 🔍 Final output after flush (first {min(len(lines),3)} lines):\n{preview}")

    # Stall logic
    stalled = stall_count >= STALL_RETRY_THRESHOLD and not output.strip()
    return output, stalled












# ------------------ RESURRECTION REGISTRY + WATCHDOG HOOKS GATEKEEPER ------------------
## This has the resurrection_gatekeeper which will use the data from the read_output_with_watchdog function above to determine if the thread actually is
## a resurrection candidate and prevent false postives for resurrection candidates.   We only want to resurrect truly dead threads
## Later on in Phase3 will reinstall tomcat on these threads.
## The saturation defense is required because there may be other corner cases whereby the thread is not successfully being resurrected 
## (Phase3). For these threads we  need to flag them for further investigation. This could be for example with a flapping node or 
## misclassified IP address, etc....

def resurrection_gatekeeper(stderr_output, stdout_output, command_status, exit_code, runtime_seconds, pid=None, ip_address=None, resurrection_registry=None, logger=None):
    """
    Determines whether resurrection should occur based on watchdog output, stderr/stdout content, command status,
    runtime heuristics, and optional registry tracking.

    Returns: Boolean → True if resurrection should occur, False otherwise.
    """

    def log_decision(message):
        if logger:
            logger.info(f"[Gatekeeper] {message}")
        else:
            print(f"[Gatekeeper] {message}")

    # 🧠 PRIMARY HEURISTIC
    if command_status == "Command succeeded" and stderr_output.strip() == "":
        log_decision("Healthy node: Command succeeded with empty STDERR. Block resurrection.")
        return False

    # 🔍 SECONDARY SIGNALS
    if exit_code == 0 and stdout_output.strip() and stderr_output.strip() == "":
        log_decision("Clean exit with STDOUT content. Block resurrection.")
        return False

    if runtime_seconds > 5 and stdout_output.strip():
        log_decision(f"Runtime {runtime_seconds}s with STDOUT. Block resurrection.")
        return False

    # 🧯 Registry saturation defense
    if resurrection_registry and ip_address:
        count = resurrection_registry.get(ip_address, {}).get("resurrect_count", 0)
        if count >= 3:
            log_decision(f"IP {ip_address} hit resurrection limit. Quarantining further attempts.")
            return False

    if resurrection_registry and pid in resurrection_registry:
        log_decision(f"PID {pid} already resurrected. Block repeated action.")
        return False

    # 🔁 Default: allow resurrection
    log_decision("Resurrection allowed: no success heuristics matched.")
    return True








####### REFACTORED for the multi-processing pooling now defined in main()
####### this tomcat_worker has been refactored to be in compliance with the multi-processing pooling that is now 
####### refactored in main() (see further below)
####### This function is called by main()
####### instance_info maps to chunk the dictionary list of IPs for the process that is chunk_size IPs

def tomcat_worker(instance_info, security_group_ids, max_workers):
    import os
    import boto3
    import paramiko
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from dotenv import load_dotenv

    load_dotenv()

    #### This calls the new setup_logging() global function above for per process benchmark logging of the multi-threading
    ####  done by the ThreadPoolExecutor below
    #setup_logging()
    # comment out the setup_logging() here as it is being called from the tomcat_worker_wrapper function now. 
    # tomcat_worker_wrapper calls this tomcat_worker 
    # Try removing setup_logging in the tomcat_worker as it is called already in tomcat_worker_wrapper. This is for the empty log file per process that is being created.

    logging.info("Test log entry to ensure file is created.")



    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("region_name")
    key_path = 'EC2_generic_key.pem'
    port = 22
    username = 'ubuntu'

    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    my_ec2 = session.client('ec2')

    #commands = [
    #    
    #    #"bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt update -y 2>&1'"

    #        
    #    'sudo DEBIAN_FRONTEND=noninteractive apt update -y 2>&1', # put STDERR and STDOUT into one stream

    #    #'sudo DEBIAN_FRONTEND=noninteractive apt update -y',
    #    

    #    

    #    # second command semantics #
    #    'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9',
    #    
    #    #'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat99',

    #    
    #    #'sudo nonexistent_binary --fail', # simulate a runtime crash or exception
    #    
    #    #'sudo bash -c "nonexistent_binary --fail; sleep 1"',  # still an issue with exit_status 5 which does not make sense

    #    #'bash -c "nonexistent_binary"',  #new test1
    #      
    #    #'bash -c \'nonexistent_binary\'',  # new test2



    #    'sudo systemctl start tomcat9',
    #    
    #    'sudo systemctl enable tomcat9'
    #]






    commands = [
        # ORIGINAL — apt update without stream collapse
        "sudo DEBIAN_FRONTEND=noninteractive apt update -y",


        # ORIGINAL — apt install without stream collapse
        "sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9",

        # Optional: apt update with collapsed streams (wrapped in bash)
        #"bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt update -y 2>&1'",

        # Optional: apt install with collapsed streams (wrapped in bash)
        #"bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9 2>&1'",


        # Optional: apt update with collapsed streams and write to file and then STDOUT
        #f"bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt update -y > /tmp/apt_output_{thread_uuid}.txt 2>&1; cat /tmp/apt_output_{thread_uuid}.txt; rm /tmp/apt_output_{thread_uuid}.txt'",
        

        # Optional: apt install with collapsed streams and write to file and then STDOUT
        #f"bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9 > /tmp/apt_output_{thread_uuid}.txt 2>&1; cat /tmp/apt_output_{thread_uuid}.txt; rm /tmp/apt_output_{thread_uuid}.txt'",
 



#### Failure commands for negative testing #####

        # Optional: simulate package failure. For apt commmands with collapsed streams this will result in a stub
        # "bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat99 2>&1'",

        # Optional: simulate runtime crash
        #"sudo nonexistent_binary --fail",

        # Optional: simulate chained failure with sleep
        # "sudo bash -c 'nonexistent_binary --fail; sleep 1'",

        # Optional: raw bash invocation
        #"bash -c 'nonexistent_binary'",




        # force a shell level failure. Not seeing STDOUT, STDERR and exit code is 0 verified with raw print of exit_code
        #"sudo bash -c 'echo test > /root/testfile'",

        # test out the strace on the echo test above. We are now getting exit_code=1 which is good but no logging
        #"strace -e write,execve -o /tmp/trace.log sudo bash -c 'echo test > /root/testfile' && cat /tmp/trace.log",
 
        # strace same as above but pipe all the strace error (-1) log lines to STDERR. The rest of the logic will take 
        # care of tagging the registry_entry status for this.
        #"strace -e write,execve -o /tmp/trace.log sudo bash -c 'echo test > /root/testfile'; grep -E ' = -1 ' /tmp/trace.log >&2",

        # strace still no STDERR with above. Try this, writing directly to /dev/stderr
        #"strace -e write,execve -o /dev/stderr sudo bash -c 'echo test > /root/testfile'",

        # apply strace with this methodology.  Write the logs to /tmp/trace.log  
        # test1 THIS IS WORKING with the added logic in install_tomcat to write the /tmp/trace.log to stderr. This throws nonzero exit
        # code and also injected stderr, so install_failed
        #"strace -e write,execve -o /tmp/trace.log sudo bash -c 'echo test > /root/testfile'",






        # touch: cannot touch '/root/testfile': Permission denied. This is not throwing any STDOUT or STDERR and exit_code is 0
        #"sudo touch /root/testfile",

        # apply strace to the command above
        # test3 THIS IS WORKING. 
        #"strace -e write,execve -o /tmp/trace.log sudo touch /root/testfile",




        # bash: nonexistent_command: command not found
        #"bash -c \"nonexistent_command\"",

        # apply strace to the command above
        # test4 THIS IS WORKING
        #"strace -e write,execve -o /tmp/trace.log bash -c \"nonexistent_command\"",





        # small script that exits with error and writes to STDERR
        #"bash -c \"echo -e '#!/bin/bash\\necho \\\"This is stderr\\\" >&2\\nexit 1' > /tmp/fail.sh && chmod +x /tmp/fail.sh && sudo /tmp/fail.sh\"",

        # apply strace to the command above
        # test5 THIS IS WORKING
        #"strace -e write,execve -o /tmp/trace.log bash -c \"echo -e '#!/bin/bash\\necho \\\"This is stderr\\\" >&2\\nexit 1' > /tmp/fail.sh && chmod +x /tmp/fail.sh && sudo /tmp/fail.sh\"",




        ## Negative test D1 (exit_code forced to zero but non-whitelist stderr from strace to hit BLOCK3 install_failed code)
        # This one will produce exit_status of 0 but will have a non-whitelist in the stderr and so should be install_failed
        #"strace -e write,execve -o /tmp/trace.log bash -c \"echo 'error: something went wrong' >&2; exit 0\"",
        #"strace -e write,execve -o /tmp/trace.log bash -c \"python3 -c 'import sys; sys.stderr.write(\"error: something went wrong\\n\")'; exit 0\"",
        #"strace -e write,execve -o /tmp/trace.log bash -c \"python3 -c \\\"import sys; sys.stderr.write('error: something went wrong\\\\n')\\\"; exit 0\"",
        #"strace -e write,execve -o /tmp/trace.log bash -c \"python3 -c \\\"import os; os.write(2, b'error: something went wrong\\\\n')\\\"; exit 0\"",
         
        # test6 THIS IS WORKING FOR THE test D1 negative test case:
        #"strace -f -e write,execve -o /tmp/trace.log bash -c \"python3 -c \\\"import os; os.write(2, b'error: something went wrong\\\\n')\\\"; exit 0\"",




        # test7  E: Unable to locate package tomcat99 (BLOCK2 failure heuristic check install_failed)
        # THIS IS WORKING (but is stubbed; there is no error in stdout or stderr at all so this is the best we can do)
        #"sudo apt install tomcat99",


        # test case 8 (negative)  This will have an exit code of 1 but whitelisted stderr
        "strace -e write,execve -o /tmp/trace.log bash -c 'echo \"hello world\" > /tmp/testfile; exit 1'",


        ## test2 POSITIVE test case for strace (test case2)
        #"strace -e write,execve -o /tmp/trace.log bash -c 'echo \"hello world\" > /tmp/testfile'",


## More negative tests of new items added to the APT and strace whitelist






#### resume normal commands #####

        ## commands 3 and 4: 

        "sudo systemctl start tomcat9",
        
        # Optional: simulate a systemctl start failure. This is not a collapsed stream, should emit STDERR and should result in install_failed
        #"sudo systemctl start tomcat99",


        "sudo systemctl enable tomcat9"
    ]


    ## Negative testing: Inject failure into first thread only
    #target_ip = instance_info[0]['public_ip']

     


    ## Define SSH details
    #port = 22
    #username = 'ubuntu'
    #key_path = 'EC2_generic_key.pem'

    ## Commands to install Tomcat server
    #commands = [
    #    'sudo DEBIAN_FRONTEND=noninteractive apt update -y',
    #    'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9',
    #    'sudo systemctl start tomcat9',
    #    'sudo systemctl enable tomcat9'
    #]







## Need to wrap these calls to authorize_security_group_ingress with the wrapper function above at top of this file
## retry_with_backoff() .  This implements an exponential backoff on the API calls to the authorize function




#    # Add a security group rule to allow access to port 22
#    for sg_id in set(security_group_ids):
#        try:
#            my_ec2.authorize_security_group_ingress(
#                GroupId=sg_id,
#                IpPermissions=[
#                    {
#                        'IpProtocol': 'tcp',
#                        'FromPort': 22,
#                        'ToPort': 22,
#                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
#                    }
#                ]
#            )
#        except my_ec2.exceptions.ClientError as e:
#            if 'InvalidPermission.Duplicate' in str(e):
#                print(f"Rule already exists for security group {sg_id}")
#            else:
#                raise
#
#
#
#
#
#    # Add a security group rule to allow access to port 80
#    for sg_id in set(security_group_ids):
#        try:
#            my_ec2.authorize_security_group_ingress(
#                GroupId=sg_id,
#                IpPermissions=[
#                    {
#                        'IpProtocol': 'tcp',
#                        'FromPort': 80,
#                        'ToPort': 80,
#                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
#                    }
#                ]
#            )
#        except my_ec2.exceptions.ClientError as e:
#            if 'InvalidPermission.Duplicate' in str(e):
#                print(f"Rule already exists for security group {sg_id}")
#            else:
#                raise
#
#
#    # Add a security group rule to allow access to port 8080
#    for sg_id in set(security_group_ids):
#        try:
#            my_ec2.authorize_security_group_ingress(
#                GroupId=sg_id,
#                IpPermissions=[
#                    {
#                        'IpProtocol': 'tcp',
#                        'FromPort': 8080,
#                        'ToPort': 8080,
#                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
#                    }
#                ]
#            )
#        except my_ec2.exceptions.ClientError as e:
#            if 'InvalidPermission.Duplicate' in str(e):
#                print(f"Rule already exists for security group {sg_id}")
#            else:
#                raise
#

    for sg_id in set(security_group_ids):
        try:
            retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise


    for sg_id in set(security_group_ids):
        try:
            retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise



    for sg_id in set(security_group_ids):
        try:
            retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 8080,
                    'ToPort': 8080,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise









    def wait_for_instance_running(instance_id, ec2_client):
        while True:
            instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
            statuses = instance_status.get('InstanceStatuses', [])

            if statuses:
                state = statuses[0]['InstanceState']['Name']
                system_status = statuses[0]['SystemStatus']['Status']
                instance_status_check = statuses[0]['InstanceStatus']['Status']

                if state == 'running' and system_status == 'ok' and instance_status_check == 'ok':
                    break
            else:
                print(f"No status yet for instance {instance_id}. Waiting...")

            print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
            time.sleep(10)




# Function to install Tomcat on an instance
    def install_tomcat(ip, private_ip, instance_id):
        
        import uuid 
        ## install_tomcat is the definitive thread_uuid source. It is removed from calling function threaded_install
        thread_uuid = uuid.uuid4().hex[:8]




        ## wrap the showl SSH install_tomcat in try block and put an exception after it and create stub registry 
        ## for threads that throw an exception and exit.  This is for IP thread tracking forensics. This threads
        ## will be tagged with a stub registry status of 
        
        # the try block is causing very serious issues. Remove it and retest.
        #try:


        wait_for_instance_running(instance_id, my_ec2)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # debug for patch7c issues. We have isolated it to install_tomcat and the thread_registry in threaded_install
        print(f"[TRACE][install_tomcat] Beginning installation on {ip}")

########## this code block is for the SSH connection establishment code  ############
        
        ## comment out this code and replace with the new code below with failure status codes for the registry 
        ## as well as with stub registry protection in case of aborted silent for/else loop.

        #for attempt in range(5):
        #    try:
        #        print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")
        #        ssh.connect(ip, port, username, key_filename=key_path)
        #        break
        #    except paramiko.ssh_exception.NoValidConnectionsError as e:
        #        print(f"Connection failed: {e}")
        #        time.sleep(10)
        #else:
        #    print(f"Failed to connect to {ip} after multiple attempts")
        #    return ip, private_ip, False

        #print(f"Connected to {ip}. Executing commands...")



########## this is the new code for the SSH connection establishment code with registry failure tagging and ###########
########## with stub registry protection if the for/else loop is abruptly terminated with no exception      ###########
########## the stub helps a lot with forensic traceability                                                  ###########




        ssh_connected = False
        status_tagged = False
        registry_entry_created = False
        ssh_success = False  # temp flag to suppress stub

        for attempt in range(5):
            try:
                print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")

                # Start a watchdog timer in a separate thread. 
                # This is to catch mysterious thread drops and create a stub entry for those.
                # The status of stub will make them show up in the failed_ips_list rather than missing 
            
                
                # saw an exception on the watchdog thread itself so use a try/except block so that we have an error message
                # thrown in the logs if this happens again. The original error without the try/except was a generic thread
                # exception from threading.Thread

            ##### OLD CODE #####
            #    def watchdog():
            #        try:
            #            time.sleep(30)
            #            if not ssh_connected:
            #                pid = multiprocessing.current_process().pid
            #                if pid:
            #                    stub_entry = {
            #                        "status": "stub",
            #                        "attempt": -1,
            #                        "pid": pid,
            #                        "thread_id": threading.get_ident(),
            #                        "thread_uuid": thread_uuid,
            #                        "public_ip": ip,
            #                        "private_ip": private_ip,
            #                        "timestamp": str(datetime.utcnow()),
            #                        "tags": ["stub", "watchdog_triggered", "ssh_connect_stall"]
            #                    }
            #                    thread_registry[thread_uuid] = stub_entry
            #                    return ip, private_ip, stub_entry
            #        except Exception as e:
            #            print(f"[ERROR][watchdog] Exception in watchdog thread: {e}")

            #    threading.Thread(target=watchdog, daemon=True).start()
            #    ####### end of watchdog code ##########        


            #    ssh.connect(ip, port, username, key_filename=key_path)
            #    ssh_connected = True
            #    ssh_success = True  # suppress stub
            #    break  # break out of the for attempt(5) loop
            #
            #except paramiko.ssh_exception.NoValidConnectionsError as e:
            #    print(f"Connection failed: {e}")
            #    time.sleep(10)
                


            ##### NEW CODE with attempt == 4 gating #####
                def watchdog():
                    try:
                        time.sleep(30)
                        if not ssh_connected and attempt == 4:  # Only tag stub on final attempt
                            pid = multiprocessing.current_process().pid
                            if pid:
                                stub_entry = {
                                    "status": "stub",
                                    "attempt": -1,
                                    "pid": pid,
                                    "thread_id": threading.get_ident(),
                                    "thread_uuid": thread_uuid,
                                    "public_ip": ip,
                                    "private_ip": private_ip,
                                    "timestamp": str(datetime.utcnow()),
                                    "tags": ["stub", "watchdog_triggered", "ssh_connect_stall"]
                                }
                                thread_registry[thread_uuid] = stub_entry
                                return ip, private_ip, stub_entry
                    except Exception as e:
                        print(f"[ERROR][watchdog] Exception in watchdog thread: {e}")

                threading.Thread(target=watchdog, daemon=True).start()
                ####### end of watchdog code ##########

                ssh.connect(ip, port, username, key_filename=key_path)
                ssh_connected = True
                ssh_success = True  # suppress stub
                break  # break out of the for attempt(5) loop

            except paramiko.ssh_exception.NoValidConnectionsError as e:
                print(f"[{ip}] 💥 SSH connection failed on attempt {attempt + 1}: {e}")
                if attempt == 4:
                    registry_entry = {
                        "status": "install_failed",
                        "attempt": attempt,
                        "pid": multiprocessing.current_process().pid,
                        "thread_id": threading.get_ident(),
                        "thread_uuid": thread_uuid,
                        "public_ip": ip,
                        "private_ip": private_ip,
                        "timestamp": str(datetime.utcnow()),
                        "tags": ["ssh_exception", "NoValidConnectionsError", str(e)]
                    }
                    thread_registry[thread_uuid] = registry_entry
                    return ip, private_ip, registry_entry
                else:
                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    continue


        else:
            print(f"Failed to connect to {ip} after multiple attempts")
            registry_entry = {
                "status": "ssh_retry_failed",
                "attempt": -1,
                "pid": multiprocessing.current_process().pid,
                "thread_id": threading.get_ident(),
                "thread_uuid": thread_uuid,
                "public_ip": ip,
                "private_ip": private_ip,
                "timestamp": str(datetime.utcnow()),
                "tags": ["ssh_retry_failed"]
            }
            status_tagged = True
            registry_entry_created = True
            return ip, private_ip, registry_entry


        if not status_tagged and not registry_entry_created and not ssh_success:
            pid = multiprocessing.current_process().pid
            if pid:  # only stub if pid exists
                print(f"[STUB] install_tomcat ssh.connecct exited early for {ip}")
                stub_entry = {
                    "status": "stub",
                    "attempt": -1,
                    "pid": pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": ["stub", "early_exit", "ssh_init_failed"]
                }
                return ip, private_ip, stub_entry


########## these old block are for the early installation of tomcat code ###############
#        for command in commands:
#            for attempt in range(3):
#                stdin, stdout, stderr = ssh.exec_command(command)
#                stdout_output = stdout.read().decode()
#                stderr_output = stderr.read().decode()
#                print(f"Executing command: {command}")
#                print(f"STDOUT: {stdout_output}")
#                print(f"STDERR: {stderr_output}")
#
#                
#                # Check for real errors and ignore warnings
#                if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
#                    print(f"Installation failed for {ip} due to package issue.")
#                    stdin.close()
#                    stdout.close()
#                    stderr.close()
#                    ssh.close()
#                    return ip, private_ip, False
#                
#                # Ignore specific warnings that are not critical errors
#                if "WARNING:" in stderr_output:
#                    print(f"Warning on {ip}: {stderr_output}")
#                    stderr_output = ""
#                
#                if stderr_output.strip():  # If there are any other errors left after ignoring warnings
#                    print(f"Error executing command on {ip}: {stderr_output}")
#                    stdin.close()
#                    stdout.close()
#                    stderr.close()
#                    ssh.close()
#                    return ip, private_ip, False
#                
#                print(f"Retrying command: {command} (Attempt {attempt + 1})")
#                ### increase this delay for the 400/0 hyper-processing case from 10 to 20 seconds
#                #time.sleep(10)
#                time.sleep(20)
#            
#            stdin.close()
#            stdout.close()
#            stderr.close()

## UPDATED CODE FOR ABOVE BLOCK:

#        for command in commands:
#            for attempt in range(3):
#                try:
#                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
#                    stdout_output = stdout.read().decode()
#                    stderr_output = stderr.read().decode()
#
#                    print(f"Executing command: {command}")
#                    print(f"STDOUT: {stdout_output}")
#                    print(f"STDERR: {stderr_output}")
#
#                    # Check for real errors and ignore warnings 
#                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
#                        print(f"Installation failed for {ip} due to package issue.")
#                        ssh.close()
#                        return ip, private_ip, False
#                    
#                    # Ignore specific warnings that are not critical errors
#                    if "WARNING:" in stderr_output:
#                        print(f"Warning on {ip}: {stderr_output}")
#                        stderr_output = ""
#
#                    if stderr_output.strip():   # If there are any other errors left after ignoring warnings:
#                        print(f"Error executing command on {ip}: {stderr_output}")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    print(f"Retrying command: {command} (Attempt {attempt + 1})")
#                    time.sleep(20) #Increase this from 10 to 20 seconds
#                except Exception as e:
#                    print(f"[Error] exec_command timeout or failure on {ip}: {e}")
#                    ssh.close()
#                    return ip, private_ip, False
#                finally:
#                    stdin.close()
#                    stdout.close()
#                    stderr.close()

## REFACTOR SSH 1:

#        for command in commands:
#            for attempt in range(3):
#                try:
#                    print(f"[DEBUG] Starting SSH command attempt {attempt + 1} on {ip}: {command}")
#
#                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
#
#                    print(f"[DEBUG] Command sent: {command}")
#                    print(f"[DEBUG] Waiting to read stdout...")
#                    stdout_output = stdout.read().decode()
#                    print(f"[DEBUG] Waiting to read stderr...")
#                    stderr_output = stderr.read().decode()
#
#                    print(f"[DEBUG] Read complete for {ip}")
#                    print(f"[INFO] Executing command: {command}")
#                    print(f"[INFO] STDOUT length: {len(stdout_output)} chars")
#                    print(f"[INFO] STDERR length: {len(stderr_output)} chars")
#                    print(f"STDOUT: {stdout_output}")
#                    print(f"STDERR: {stderr_output}")
#
#                    # Detect specific fatal Tomcat errors early
#                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
#                        print(f"[ERROR] Fatal: No install candidate on {ip}")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    # Warning softener
#                    if "WARNING:" in stderr_output:
#                        print(f"[WARN] Non-fatal warning on {ip}: {stderr_output}")
#                        stderr_output = ""
#
#                    # Catch any remaining stderr (actual failures)
#                    if stderr_output.strip():
#                        print(f"[ERROR] Command error output on {ip}: {stderr_output}")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    print(f"[DEBUG] Retrying command: {command} (Attempt {attempt + 1})")
#                    time.sleep(20)
#
#                except Exception as e:
#                    print(f"[EXCEPTION] exec_command failed on {ip}: {e}")
#
#                    # Log partial output if available
#                    try:
#                        if stdout:
#                            stdout_output = stdout.read().decode()
#                            print(f"[EXCEPTION DEBUG] Partial STDOUT ({len(stdout_output)}): {stdout_output}")
#                        if stderr:
#                            stderr_output = stderr.read().decode()
#                            print(f"[EXCEPTION DEBUG] Partial STDERR ({len(stderr_output)}): {stderr_output}")
#                    except Exception as inner:
#                        print(f"[EXCEPTION] Error reading from stdout/stderr after failure: {inner}")
#
#                    ssh.close()
#                    return ip, private_ip, False
#
#                finally:
#                    if stdin: stdin.close()
#                    if stdout: stdout.close()
#                    if stderr: stderr.close()
#
#


## REFACTOR SSH 2:

#
#        from datetime import datetime
#
#        for idx, command in enumerate(commands):
#            for attempt in range(3):
#                try:
#                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
#                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
#
#
#                    ## Add this timout code to detect why some instances are silently failing without hitting my except block below
#                    ## this will force it out of the try loop to execept bloc.
#
#                    # 🔒 Ensure the VPS doesn’t hang forever waiting on output
#                    stdout.channel.settimeout(90)
#                    stderr.channel.settimeout(90)
#
#                    stdout_output = stdout.read().decode()
#                    stderr_output = stderr.read().decode()
#
#                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
#                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")
#
#                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
#                        print(f"[{ip}] [{datetime.now()}] ❌ Package install failure. Exiting early.")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    if "WARNING:" in stderr_output:
#                        print(f"[{ip}] [{datetime.now()}] ⚠️ Warning ignored: {stderr_output.strip()}")
#                        stderr_output = ""
#
#                    if stderr_output.strip():
#                        print(f"[{ip}] [{datetime.now()}] ❌ Non-warning error output. Command failed.")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    print(f"[{ip}] [{datetime.now()}] ✅ Command succeeded.")
#                    time.sleep(20)
#
#                except Exception as e:
#                    print(f"[{ip}] [{datetime.now()}] 💥 Exception during exec_command: {e}")
#                    ssh.close()
#                    return ip, private_ip, False
#
#                finally:
#                    stdin.close()
#                    stdout.close()
#                    stderr.close()
#
#
#        ssh.close()
#        transport = ssh.get_transport()
#        if transport is not None:
#            transport.close()
#        print(f"Installation completed on {ip}")
#        return ip, private_ip, True
#
#



### REFACTOR SSH 3 – Phase 1: Retry + Watchdog Protection
### The stdout and stderr are now wrapped in the watchdog function read_output_with_watchdog
#
#        from datetime import datetime
#        import time
#
#        WATCHDOG_TIMEOUT = 90
#        RETRY_LIMIT = 3
#        SLEEP_BETWEEN_ATTEMPTS = 5
#
#        def read_output_with_watchdog(stream, label, ip):
#            start = time.time()
#            collected = b''
#            while True:
#                if stream.channel.recv_ready():
#                    try:
#                        collected += stream.read()
#                        break
#                    except Exception as e:
#                        print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
#                        break
#                if time.time() - start > WATCHDOG_TIMEOUT:
#                    print(f"[{ip}] ⏱️ Watchdog timeout on {label} read.")
#                    break
#                time.sleep(1)
#            return collected.decode()
#
#        for idx, command in enumerate(commands):
#            for attempt in range(RETRY_LIMIT):
#                try:
#                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
#                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
#
#                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
#                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)
#
#                    stdout_output = read_output_with_watchdog(stdout, "STDOUT", ip)
#                    stderr_output = read_output_with_watchdog(stderr, "STDERR", ip)
#
#                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
#                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")
#
#                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
#                        print(f"[{ip}] ❌ Tomcat install failure.")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    if "WARNING:" in stderr_output:
#                        print(f"[{ip}] ⚠️ Warning ignored: {stderr_output.strip()}")
#                        stderr_output = ""
#
#                    if stderr_output.strip():
#                        print(f"[{ip}] ❌ Non-warning stderr received.")
#                        ssh.close()
#                        return ip, private_ip, False
#
#                    print(f"[{ip}] ✅ Command succeeded.")
#                    time.sleep(20)
#                    break  # Command succeeded, no need to retry
#
#                except Exception as e:
#                    print(f"[{ip}] 💥 Exception during exec_command: {e}")
#                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)
#
#                finally:
#                    stdin.close()
#                    stdout.close()
#                    stderr.close()
#
#

## REFACTOR SSH 4 - Phase 2 The new resurrection policy to flag connecitons that have failed 2 watchdog timeouts
## and update resurrection registry.  Multiple stalls detected. Flagging for resurrection
## Note the read_output_with_watchdog function and an new function update_resurrection_registry have been added/moved to just
## above the main tomcat_worker function above. This makes them global so that we can utilize the resurrection monitor
## that will log the resurrection registry candidates.   These functions are now global to tomcat_worker (not indented).
## The comment # ------------------ RESURRECTION REGISTRY + WATCHDOG HOOKS ------------------ flags the block.
## The read_output_with_watchdog calls the update_resurrection_registry function





        #NON-Negative testing use this: (and comment out the above)
        for idx, command in enumerate(commands):

            ## Negative testing:
            #if ip == target_ip and idx == 1:
            #    command = 'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat99'



        ## the commands are listed at the top of tomcat_worker(), the calling function. There are 4 of them. These can
        ## be modified for any command installation type (any application)

            ## Code for the conidtional registry entry if hit install error: First, Add a success flag before the attempt loop 
            ## set the command_succeeded flag to the default of False BEFORE the for attempt loop
            ## This flag is used to gate the install_failed registry_entry block after the for attempt loop IF
            ## the install_succeeded and break (out of the for attempt loop). This is to prevent a install_failed on
            ## successful installs and preserve the failure logic if the for attempt loop aborts
            command_succeeded = False





###### Major overhaul of the "for attempt" command loop below to support whitelist filtering for agnostic output 
###### flush analysis of thread STDOUT and STDERR so that the registry_entry can be assigned a status
######  BLOCKS 1, 2,3 and 4 are to be reordered as shown below, and BLOCK 3 is completely replaced with new 
###### whitelist based decison making. The whitelist is defined at the top of this module APT_WHITELIST_REGEX 
###### and will be generalized to be stream/app agnostic at some point
###### The helper function is_whitelisted_line is also defined at the top of this module.
###### BLOCK number refers to NEW#(ORIGINAL#)

            for attempt in range(RETRY_LIMIT):
            ## the inner attempt loop will try up to RETRY_LIMIT = 3 number of times to install the particular command
            ## each attempt (of 3) will use the adaptive WATCHDOG_TIMEOUT as a watchdog and if the watchdog expires it
            ## can re-attempt for STALL_RETRY_THRESHOLD =2 number of times watchdogs on each command attemp (of 3 total)

                try:
                    
#### BLOCK1(1) is the STDOUT and STDERR output flush from read_output_with_watchdog function

                    #BLOCK1(1)

                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
                   
                    ## Place this before teh stdin, stdout, stderr = ssh.exec_command(command) for the strace commands
                    ## This important block of code generates a random number trace log file suffix so that the trace.log
                    ## file for the strace is unique per thread, per command and per retry of command. This prevents cross
                    ## contamination of the strace output which is eventually injected into the stderr to determine the thread
                    ## status. THe wrapper function for strace will conataine /tmp/trace.log by default and this is the 
                    ## replacement string for trace_trace_suffix.log
                    if "strace" in command:
                        trace_suffix = generate_trace_suffix()
                        trace_path = f"/tmp/trace_{trace_suffix}.log"
                        command = command.replace("/tmp/trace.log", trace_path)





                    #try pty for debugging
                    #stdin, stdout, stderr = ssh.exec_command(command, timeout=60, get_pty=True)
                                                            
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)


                    ## Debugging the blank STDERR issue with RAW
                    #raw_stdout = stdout.read()
                    #raw_stderr = stderr.read()
                    #print(f"[{ip}] RAW STDOUT: {repr(raw_stdout)}")
                    #print(f"[{ip}] RAW STDERR: {repr(raw_stderr)}")
                    ## end debug

                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)


                    #stdout_output = read_output_with_watchdog(stdout, "STDOUT", ip, attempt)
                    #stderr_output = read_output_with_watchdog(stderr, "STDERR", ip, attempt)

                    #print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    #print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")


                    stdout_output, stdout_stalled = read_output_with_watchdog(stdout, "STDOUT", ip)
                    stderr_output, stderr_stalled = read_output_with_watchdog(stderr, "STDERR", ip)

                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")
                    




## Insert BLOCK2(4) here, before the new whitelist code. This is the failure heuristic code.


##### This block BLOCK2(4)needs to be moved after BLOCK1(1) and before BLOCK3(2)
##### The failure heuristics can be applied without whitelist filtering as these are known errors

                    # FAILURE HEURISTICS: BLOCK2(4)

                    # 🔴 Fatal error: missing tomcat9 package — tag and return
                   

                    #if "E: Package 'tomcat9'" in stderr_output:
                    #    print(f"[{ip}] ❌ Tomcat install failure.")
                    #    ssh.close()
                    #    return ip, private_ip, False
                    #    # this error is a critical error so return to calling thread but need to set registry


                    #if "E: Package 'tomcat9'" in stderr_output:
                    #    print(f"[{ip}] ❌ Tomcat install failure — package not found.")
                    #    registry_entry = {
                    #        "status": "install_failed",
                    #        "attempt": -1,
                    #        "pid": multiprocessing.current_process().pid,
                    #        "thread_id": threading.get_ident(),
                    #        "thread_uuid": thread_uuid,
                    #        "public_ip": ip,
                    #        "private_ip": private_ip,
                    #        "timestamp": str(datetime.utcnow()),
                    #        "tags": ["fatal_package_missing", command]
                    #    }
                    #    ssh.close()
                    #    return ip, private_ip, registry_entry

                    
                    ## Modify the above to fail ONLY if it is the LAST attempt> we do not want to prematurely create stubs
                    ## and failed registry entries uniless all retries have been exhausted

                    #BLOCK2(4)
                    if "E: Package 'tomcat9'" in stderr_output:
                        if attempt == RETRY_LIMIT - 1:
                            print(f"[{ip}] ❌ Tomcat install failure — package not found on final attempt.")
                            registry_entry = {
                                "status": "install_failed",
                                "attempt": -1,
                                "pid": multiprocessing.current_process().pid,
                                "thread_id": threading.get_ident(),
                                "thread_uuid": thread_uuid,
                                "public_ip": ip,
                                "private_ip": private_ip,
                                "timestamp": str(datetime.utcnow()),
                                "tags": [
                                    "fatal_package_missing",
                                    command,
                                    f"command_retry_{attempt + 1}",  # e.g. command_retry_3
                                    *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                ]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Package not found — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue  # skip the rest of the for attempt loop and iterate to the next attempt fo this current
                            # for idx command.




                    # ⚠️ Non-fatal warning — clear stderr and proceed
                    if "WARNING:" in stderr_output:
                        print(f"[{ip}] ⚠️ Warning ignored: {stderr_output.strip()}")
                        stderr_output = ""
                        # clear the stderr output








## BLOCK3(2)
## comment out the entire block below for new code below this.  The new code has new logic based upon STDERR output from
## read_output_with_watchdog and also using exit_status and the command attempt iteration of this for attempt loop
## The watchdog in read_output_with_watchdog is designed for stream stall detection and not failure detection.
## Failure detection is done in the new code in this install_tomcat function.

                    ### OLD CODE:(this was using the watchdog for failure detection. This does not work right
                    ### only stub the thread if stdout_stalled AND stderr_stalled (from read_output_with_watchdog) AND
                    ### Attempts on the command is at the RETRY_LIMIT (see for attempt loop above).  Note that
                    ### attempt starts at 0 and the for attempt uses range RETRY_LIMIT so for 3 that is [0,1,2] thus
                    ### use RETRY_LIMIT -1 in the if statement below.

                    ##if stdout_stalled and stderr_stalled:
                    #    
                    #if stdout_stalled and stderr_stalled and attempt == RETRY_LIMIT - 1:
                    #    # Only tag as stub on final retry

                    #    #print(f"[{ip}] ❌ Streams stalled on final attempt — tagging stub")
                    #    ## Proceed with stub tagging logic here
                    #    #print(f"[{ip}] ⏱️ Watchdog stall threshold reached — tagging stub for command {idx + 1}/4.")
                    #    
                    #    print(f"[{ip}] ❌ Final attempt stalled — tagging stub for command {idx + 1}/4.")


                    #    stub_entry = {
                    #        "status": "stub",
                    #        "attempt": -1,
                    #        "pid": multiprocessing.current_process().pid,
                    #        "thread_id": threading.get_ident(),
                    #        "thread_uuid": thread_uuid,
                    #        "public_ip": ip,
                    #        "private_ip": private_ip,
                    #        "timestamp": str(datetime.utcnow()),
                    #        "tags": ["stub", f"watchdog_install_timeout_command_{idx}", "stall_retry_threshold", command]
                    #    }
                    #    return ip, private_ip, stub_entry


                    #else:
                    #    if stdout_stalled and stderr_stalled:
                    #        print(f"[{ip}] 🔄 Streams stalled but retrying (attempt {attempt + 1} of {RETRY_LIMIT})")





#### Comment out original BLOCK3(2)(Below) and replace this with the new whitelist based filtering logic below

                    ### NEW REVISED CODE:
                    ### Logic:
                    ### | Condition | Action |
                    ###|----------|--------|
                    ###| `exit_status != 0` or `stderr_output.strip()` | Retry (continue) or tag failure depending on attempt |
                    ###| `exit_status == 0` and `stderr_output.strip() == ""` | Mark command as succeeded |
                    ###| After all commands succeed | Tag `install_success` outside the `for idx` loop |
                    ###

                    ### Examples:
                    ###Condition | Outcome | Reason |
                    ###|----------|---------|--------|


                    ### exit_status !=0
                    ###| `stderr_output.strip()` is non-empty AND all command attempts exhausted | `install_failed` | 
                    ###We know what went wrong — stderr gives us the cause |

                    ### exit_status !=0
                    ###| `stderr_output.strip()` is empty AND all command attempts exhausted | `stub` | Silent failure — 
                    ###no output, no clue what happened |   NOTE: this is only our 4th stub. The criteria for a stub is 
                    ###very strict.

                    ### exit_status =0
                    ###| Any attempt succeeds (exit_status=0, no fatal stderr) command succeeded | No need to retry or tag 
                    ###failure . This will bypass all stub and failure registry logic and command succeeded will be reached at 
                    ###the bottom of install_tomcat. If all commands execute in this fashion the registry_entry will be status 
                    ###install_success (outside of the for idx loop).  Note that exit_status is 0 in this case

                    ## BLOCK3(2)
                    #exit_status = stdout.channel.recv_exit_status()
                    #if exit_status != 0 or stderr_output.strip():
                    #    print(f"[{ip}] ❌ Command failed — exit status {exit_status}, stderr: {stderr_output.strip()}")
                    #    
                    #    if attempt == RETRY_LIMIT - 1:
                    #        # Final attempt — tag failure
                    #        if stderr_output.strip():
                    #            registry_entry = {
                    #                "status": "install_failed",
                    #                "attempt": -1,
                    #                "pid": multiprocessing.current_process().pid,
                    #                "thread_id": threading.get_ident(),
                    #                "thread_uuid": thread_uuid,
                    #                "public_ip": ip,
                    #                "private_ip": private_ip,
                    #                "timestamp": str(datetime.utcnow()),
                    #                "tags": [
                    #                    "fatal_error",
                    #                    command,
                    #                    f"command_retry_{attempt + 1}"  # Optional, for forensic clarity
                    #                ]
                    #            }

                    #        else:
                    #            pid = multiprocessing.current_process().pid
                    #            if pid:
                    #                registry_entry = {
                    #                    "status": "stub",
                    #                    "attempt": -1,
                    #                    "pid": pid,
                    #                    "thread_id": threading.get_ident(),
                    #                    "thread_uuid": thread_uuid,
                    #                    "public_ip": ip,
                    #                    "private_ip": private_ip,
                    #                    "timestamp": str(datetime.utcnow()),
                    #                    "tags": ["silent_failure", 
                    #                        command, 
                    #                        f"command_retry_{attempt + 1}",
                    #                        "exit_status_nonzero_stderr_blank"
                    #                    ]
                    #                }
                    #                return ip, private_ip, registry_entry
                    #            else:
                    #                print(f"[{ip}] ⚠️ Stub skipped — missing PID on final attempt for silent failure.")
                    #                return ip, private_ip, None  # Or fallback logic if needed
    
                    #    else:
                    #        # Retry the command
                    #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    #        continue  # the continue is critical. If the retry limit is not reached exit entirely out of this
                    #    # for attempt loop and go to the next attempt iteration of the same command (give it another try).
                    #    # all the falure and success logic below will be bypassed which is what we want.





##### New whitelist decision making code replacing orignal BLOCK3(2) above. The basic logic constructs are intact with
##### the exit_status, RETRY_LIMIT, STDERR output being the main decision making criteria, but also adding in the 
##### whitelist as well, for apps that don't behave well with STDOUT and STDERR channel separation.  With these types of
##### installs, STDERR is very dirty and needs to be filtered through the whitelist.


                    exit_status = stdout.channel.recv_exit_status()
                    #log.info(f"[{ip}] Raw exit status from SSH channel: {exit_status}") # debug the negative test case issues
                    print(f"[{ip}] Raw exit status from SSH channel: {exit_status}")

                    # Inject strace output into stderr_output if needed
                    # Optional trace dump if command was wrapped with strace
                    # strace is required on commands that are bash or bash-like. Will write the wrapper function for this
                    # and the pre-processing for this later. Right now testing with single strace command 
                    

                    
                    ####### Comment out the original strace logic for the refactored logic below this.  
                    ####### The refactored code has to be placed after the non_whitelisted_lines
                      
                   # #if "strace" in command and not stderr_output.strip():
                   # if "strace" in command and exit_status != 0 and not stderr_output.strip():

                   #     trace_in, trace_out, trace_err = ssh.exec_command("cat /tmp/trace.log")
                   #     trace_output = trace_out.read().decode()
                   #     print(f"[{ip}] strace output:\n{trace_output}")
                   #     stderr_output = trace_output  # Inject into failure logic
                   #     
                   #     # make sure to use stderr_output here so that we inject the strace stderr from the print into 
                   #     # teh stderr_output_strip below so that it can be used in all the falure and whitelist logic
                   #     # Note that the whitelist has been updated for strace (in addtion to the apt already there).
                   #     # Now all the logic below can be used to filter these bash and bash like commands. Will do the 
                   #     # wrapper function and the pre-processing for this later.

                   
                    if "strace" not in command:

                        ## non-whitelisted lines in stderr to detect true errors in stderr. This filters out whitelisted items
                        ## that may leak in from stdout to stderr with apt and also for other package installers as defined by
                        ## their specific whitelists. Also used for strace logic.
                        stderr_lines = stderr_output.strip().splitlines()
                        non_whitelisted_lines = [line for line in stderr_lines if not is_whitelisted_line(line)]

                        print(f"[{ip}] Non-whitelisted stderr lines: {non_whitelisted_lines}")

                        ## non-whitelisted lines in stdout (basically blacklisted lines) to detect errors in stdout
                        stdout_lines = stdout_output.strip().splitlines()
                        stdout_blacklisted_lines = [line for line in stdout_lines if not is_whitelisted_line(line)]

                        print(f"[{ip}] Blacklisted stdout lines: {stdout_blacklisted_lines}")




                    ############# New refactored strace code ############
                    # This was done to handle corner cases as well as to integrate with the strace wrapper and pre-processing
                    # functions that are too be added. This block must be placed after the non_whitelisted_lines

                    #if "strace" in command and not stderr_output.strip():
                    #    # --- STRACE SPECIAL LOGIC ---
                    #    # If this is a strace-wrapped command and there is no original stderr,
                    #    # inject the strace trace log into stderr_output for downstream error logic.
                    #    trace_in, trace_out, trace_err = ssh.exec_command(f"cat /tmp/trace_{thread_uuid}.log")
                    #    trace_output = trace_out.read().decode()
                    #    print(f"[{ip}] strace output:\n{trace_output}")
                    #    stderr_output = trace_output  # Inject strace output into stderr
                    #    
                    #    # Parse trace output for whitelist filtering
                    #    stderr_lines = stderr_output.strip().splitlines()
                    #    non_whitelisted_lines = [line for line in stderr_lines if not is_whitelisted_line(line)]


                    # Revised to support distinct trace.log file names per thread per command per retry
                    if "strace" in command and not stderr_output.strip():
                        # --- STRACE SPECIAL LOGIC ---
                        # If this is a strace-wrapped command and there is no original stderr,
                        # inject the strace trace log into stderr_output for downstream error logic.

                        # Extract the trace path from the command string. if strace, the command has been pre-processed with a
                        # unique trace path/trace.log filename
                        trace_path = command.split("-o")[1].split()[0].strip()

                        trace_in, trace_out, trace_err = ssh.exec_command(f"cat {trace_path}")
                        trace_output = trace_out.read().decode()

                        print(f"[{ip}] strace output:\n{trace_output}")
                        stderr_output = trace_output  # Inject strace output into stderr

                        # from the trace_output (injected into stderr_output) parse out the actual exit status of the 
                        # wrapped command and not of strace itself (which is based on 
                        # exit_status = stdout.channel.recv_exit_status())
                        # This resets the exit_status to the correct value for strace commands so that they can be 
                        # logically failed or passed
                        match = re.search(r"\+\+\+ exited with (\d+) \+\+\+", trace_output)
                        if match:
                            exit_status = int(match.group(1))
                            print(f"[{ip}] 🔍 Overriding exit status from strace: {exit_status}")


                        # Parse trace output for whitelist filtering and do the printout for strace case:
                        # (same as the non-strace case; see above)
                        stderr_lines = stderr_output.strip().splitlines()
                        non_whitelisted_lines = [line for line in stderr_lines if not is_whitelisted_line(line)]
                        print(f"[{ip}] Non-whitelisted stderr lines: {non_whitelisted_lines}")

                        stdout_lines = stdout_output.strip().splitlines()
                        stdout_blacklisted_lines = [line for line in stdout_lines if not is_whitelisted_line(line)]
                        print(f"[{ip}] Blacklisted stdout lines: {stdout_blacklisted_lines}")




                        # --- NONZERO EXIT CODE CASE ---
                        # If the exit code is nonzero, we do NOT need to check for non-whitelisted lines.
                        # The presence of a nonzero exit code is sufficient to fail the command.
                        # We inject the strace output so the downstream registry entry will have the correct stderr context.
                        
                        #if exit_status != 0:
                        #    # Injected stderr_output will now be handled by generic nonzero exit logic outside this block.
                        #    # Do nothing here, fall through to generic error logic outside this block.Exit this strace if
                        #    # block with continue. Let that code evaluate the status of the thread.
                        #    #pass
                        #    continue


                        if exit_status != 0:
                            if attempt == RETRY_LIMIT - 1:
                                pid = multiprocessing.current_process().pid
                                thread_id = threading.get_ident()
                                timestamp = str(datetime.utcnow())

                                if stderr_output.strip():
                                    registry_entry = {
                                        "status": "install_failed",
                                        "attempt": -1,
                                        "pid": pid,
                                        "thread_id": thread_id,
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": timestamp,
                                        "tags": [
                                            "fatal_exit_nonzero",
                                            command,
                                            f"command_retry_{attempt + 1}",
                                            f"exit_status_{exit_status}",
                                            "stderr_present",
                                            *non_whitelisted_lines[:4],  # include first few lines for forensic trace
                                            *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                        ]
                                    }
                                else:
                                    registry_entry = {
                                        "status": "stub",
                                        "attempt": -1,
                                        "pid": pid,
                                        "thread_id": thread_id,
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": timestamp,
                                        "tags": [
                                            "silent_failure",
                                            command,
                                            f"command_retry_{attempt + 1}",
                                            f"exit_status_{exit_status}",
                                            "exit_status_nonzero_stderr_blank"
                                        ]
                                    }
                                ssh.close()
                                return ip, private_ip, registry_entry

                            else:
                                print(f"[{ip}] ⚠️ Non-zero exit — retrying attempt {attempt + 1}")
                                time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                                continue


                        # --- ZERO EXIT CODE + NON-WHITELISTED STDERR CASE (D1 BLOCK3) ---
                        # If we get here, exit_status == 0, so we must check for non-whitelisted lines.
                        # This is the special case where strace reveals hidden stderr anomalies despite a clean exit code.
                        if non_whitelisted_lines:
                            # Only elevate to install_failed on the final retry attempt.
                            if attempt == RETRY_LIMIT - 1:
                                pid = multiprocessing.current_process().pid
                                thread_id = threading.get_ident()
                                timestamp = str(datetime.utcnow())

                                registry_entry = {
                                    "status": "install_failed",
                                    "attempt": -1,
                                    "pid": pid,
                                    "thread_id": thread_id,
                                    "thread_uuid": thread_uuid,
                                    "public_ip": ip,
                                    "private_ip": private_ip,
                                    "timestamp": timestamp,
                                    "tags": [
                                        "stderr_detected",
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        "exit_status_zero",   # We know exit_status is zero here.
                                        "non_whitelisted_stderr",
                                        *non_whitelisted_lines[:4],  # First few lines for traceability.
                                        *stderr_output.strip().splitlines()[:12]  # Snapshot for traceability.
                                    ]
                                }
                                ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up trace log
                                ssh.close()
                                return ip, private_ip, registry_entry
                            else:
                                print(f"[{ip}] ⚠️ Unexpected strace stderr — retrying attempt {attempt + 1}")
                                ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before retry
                                time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                                continue



                    ## Optional trace dump if command was wrapped with strace
                    ## strace is required on commands that are bash or bash-like. Will write the wrapper function for this
                    ## and the pre-processing for this later. Right now testing with single strace command 
                    #if "strace" in command and exit_status != 0 and not stderr_output.strip():
                    #    trace_in, trace_out, trace_err = ssh.exec_command("cat /tmp/trace.log")
                    #    trace_output = trace_out.read().decode()
                    #    print(f"[{ip}] strace output:\n{trace_output}")
                    #    sys.stderr.write(f"[{ip}] strace STDERR output:\n{trace_output}\n")
                    #    # write the print above(trace_output) to STDERR
                    #    # Now all the existing complex logic below can be used to filter these types of commands.

 

                    ## non-strace logic: 

                    #print(f"[{ip}] ✅ Final exit_status used for registry logic: {exit_status}")


                    # 🔍 Case 1: Non-zero exit status — failure or stub
                    if exit_status != 0:
                        if attempt == RETRY_LIMIT - 1:
                            pid = multiprocessing.current_process().pid
                            thread_id = threading.get_ident()
                            timestamp = str(datetime.utcnow())

                            if stderr_output.strip():
                                registry_entry = {
                                    "status": "install_failed",
                                    "attempt": -1,
                                    "pid": pid,
                                    "thread_id": thread_id,
                                    "thread_uuid": thread_uuid,
                                    "public_ip": ip,
                                    "private_ip": private_ip,
                                    "timestamp": timestamp,
                                    "tags": [
                                        "fatal_exit_nonzero",
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        f"exit_status_{exit_status}",
                                        "stderr_present",
                                        *non_whitelisted_lines[:4],  # include first few lines for forensic trace
                                        *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                    ]
                                }
                            else:
                                registry_entry = {
                                    "status": "stub",
                                    "attempt": -1,
                                    "pid": pid,
                                    "thread_id": thread_id,
                                    "thread_uuid": thread_uuid,
                                    "public_ip": ip,
                                    "private_ip": private_ip,
                                    "timestamp": timestamp,
                                    "tags": [
                                        "silent_failure",
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        f"exit_status_{exit_status}",
                                        "exit_status_nonzero_stderr_blank"
                                    ]
                                }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Non-zero exit — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

                    # 🔍 Case 2: Zero exit but non-whitelisted stderr — unexpected failure
                    elif non_whitelisted_lines:
                        if attempt == RETRY_LIMIT - 1:
                            pid = multiprocessing.current_process().pid
                            thread_id = threading.get_ident()
                            timestamp = str(datetime.utcnow())

                            registry_entry = {
                                "status": "install_failed",
                                "attempt": -1,
                                "pid": pid,
                                "thread_id": thread_id,
                                "thread_uuid": thread_uuid,
                                "public_ip": ip,
                                "private_ip": private_ip,
                                "timestamp": timestamp,
                                "tags": [
                                    "stderr_detected",
                                    command,
                                    f"command_retry_{attempt + 1}",
                                    "exit_status_zero",
                                    "non_whitelisted_stderr",
                                    *non_whitelisted_lines[:4],  # include first few lines for traceability
                                    *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                ]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Unexpected stderr — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

                    # ✅ Case 3: Success — zero exit and all stderr lines whitelisted
                    else:
                        print(f"[{ip}] ✅ Command succeeded.")
                        command_succeeded = True

                        #if "strace" in command:  ## clear trace1
                        #    ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Optional, but consistent for the strace case

                        time.sleep(20)
                        break


## This block below is from faiure heuristics BLOCK2(4) above. This is a last resort catchall.
##- **Edge cases** where `STDERR` is present but doesn’t match any known fatal pattern
##- **Crash scenarios** where `STDERR` is truncated or malformed
##- **Future commands** that emit unexpected output not yet covered by heuristics or whitelist
##- It catches **any `STDERR` that slips through** due to:
##  - Regex misfires
##  - Encoding issues
##  - Unexpected formatting
##- It acts as a **final safety net** in case the whitelist logic fails silently or doesn’t cover a new edge case
##- It ensures that **every command attempt is accounted for**, even if something goes wrong mid-evaluation


                    ## ⚠️ Unexpected stderr — retry instead of exiting
                    #if stderr_output.strip():
                    #    #print(f"[{ip}] ❌ Non-warning stderr received.")
                    #    
                    #    #ssh.close()
                    #    #return ip, private_ip, False
                    #    # this is not a criitical error. Will set a continue to give another retry (of 3) instead
                    #    # of ssh.close and return to calling function

                    #    print(f"[{ip}] ❌ Unexpected stderr received — retrying: {stderr_output.strip()}")
                    #    continue  # Retry the attempt loop



                    ## Modify the above to fail ONLY if it is the LAST attempt> we do not want to prematurely create stubs
                    ## and failed registry entries uniless all retries have been exhausted
                    # ⚠️ Unexpected stderr — retry instead of exiting
                    if stderr_output.strip():
                        if attempt == RETRY_LIMIT - 1:
                            print(f"[{ip}] ❌ Unexpected stderr on final attempt — tagging failure")
                            registry_entry = {
                                "status": "install_failed",
                                "attempt": -1,
                                "pid": multiprocessing.current_process().pid,
                                "thread_id": threading.get_ident(),
                                "thread_uuid": thread_uuid,
                                "public_ip": ip,
                                "private_ip": private_ip,
                                "timestamp": str(datetime.utcnow()),
                                "tags": [
                                    "stderr_detected",
                                    command,
                                    f"command_retry_{attempt + 1}",  # e.g. command_retry_3
                                    *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                ]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Unexpected stderr — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue


##### BLOCK4(3) is the resurrection legacy code. This will be refactored at some point.

                    ## Insert the call to the resurrection_gatekeeper here now that read_output_with_watchdog has collected all 
                    ## the relevant arguments for this function call

                    # BLOCK4(3)
                    should_resurrect = resurrection_gatekeeper(
                        stderr_output=stderr_output,
                        stdout_output=stdout_output,
                        command_status="Command succeeded",
                        exit_code=0,  # If you start capturing this via exec_command(), update accordingly
                        runtime_seconds=WATCHDOG_TIMEOUT,  # You can optionally measure actual elapsed time if available
                        pid=multiprocessing.current_process().pid,
                        ip_address=ip,
                        resurrection_registry=resurrection_registry
                    )

                    if should_resurrect:
                        update_resurrection_registry(ip, attempt, "gatekeeper_resurrect", pid=multiprocessing.current_process().pid)
                        print(f"[{ip}] 🛑 Resurrection triggered by gatekeeper logic.")
                    else:
                        print(f"[{ip}] ✅ Resurrection blocked — gatekeeper verified node success.")






##### BLOCK5(5) Command succeeded default

                    print(f"[{ip}] ✅ Command succeeded.")
                    ## set the command_succeeded flag to True if installation of the command x of 4 succeeded
                    ## this will gate the install_failed registry_entry following this "for attempt" block
                    ## The successful install can then proceed to the next for idx command (outer loop) and once
                    ## the for idx loop is done it will proceed through the code to the registry_entry install_succeeded
                    
                    command_succeeded = True
                    
                    #if "strace" in command:  ## clear trace2
                    #    ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before next command for strace

                    time.sleep(20)
                    break  # Success. This is a break out of the for attempt loop. The install_failed registry_entry logic
                    # is gated so that it will not fire if there is this break for Success




##### except block for the try block above

                except Exception as e:
                    print(f"[{ip}] 💥 Exception during exec_command (Attempt {attempt + 1}): {e}")
                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    # Tag as install_failed with exception details. This is part of the traceability for the install_tomcat
                    # thread forensics.  
                    registry_entry = {
                        "status": "install_failed",
                        "attempt": -1,
                        "pid": multiprocessing.current_process().pid,
                        "thread_id": threading.get_ident(),
                        "thread_uuid": thread_uuid,
                        "public_ip": ip,
                        "private_ip": private_ip,
                        "timestamp": str(datetime.utcnow()),
                        "tags": [
                            "install_for_attempt_loop_abort",
                            f"exception_{type(e).__name__}",
                            command,
                            f"command_retry_{attempt + 1}"  # e.g. command_retry_2
                        ]
                    }
                    return ip, private_ip, registry_entry



#### finally block for the "for attempt loop"
#### This executes even if a break or continue in the for attempt loop. We need to clear the trace.log between command
#### retry attempts

                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()
                
                    #if "strace" in command:  ## clear trace3
                    #    ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before next retry for strace




                ## END of the for attempt loop 



            # insert patch7b debug here for the inner attempt for loop
            #print(f"[TRACE][install_tomcat] Attempt loop ended — preparing to return for {ip}")

            ## Keep the trace oustide of the failure block below. This is so that each command will get a TRACE message
            ## For successful commands all four 1/4 through 4/4 will get a print message
            ## For the failure case (if the for attempt loop exhausts after 3 retries), the print will also be done
            # Always print when attempt loop ends — success or failure. Note for the success case for all 4 commands
            # there will be 4 prints for the ip/threas
            
            #print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip}")

            #print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip} — Success flag: {command_succeeded}")



            print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/{len(commands)}: '{command}' on IP {ip} — Success flag: {command_succeeded}")


            # This is outside of the for attempt loop. If there is NO successful attempt the loop will be exited
            # The default setting for command_succeeded is False and so this value will be False and the code block
            # below will execute setting the registry_entry to install_failed with a tag of the command that failed
             
            # This ensures: - If the command succeeds, we skip the failure block  - The outer `for idx` loop continues to
            # the next command  - Only true failures are tagged and returned
            # Note that the attempt -1 is required for the registry_entry because there has to be an attempt field in the
            # registry.   The -1 is used as a filler for failed command registry entries.

            # this block does catch silent failures inside the for attempt loop, as long as the loop completes 
            # without success or exception. If the for attempt loop silently aborts and code flow returns to threaded_install,
            # the calling function, there is stub logic there as well to create a stub registry_entry

            if not command_succeeded:
                #print(f"[TRACE][install_tomcat] Attempt loop ended — preparing to return for {ip}")
                registry_entry = {
                    "status": "install_failed",
                    "attempt": -1,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": [f"install_failed_command_{idx}", command]
                }
                
                # Optional: close SSH connection if don't plan to resurrect
                # Most likely will keep the SSH connection open so that it can be easily resurrected on the same SSH connection
                # This is becasue teh SSH connection is okay, it is just the installation commands that are failing.
                
                #ssh.close()

                return ip, private_ip, registry_entry # the return will return this registry_entry to threaded_install()
                # and the thread_registry, which will be returned to tomcat_worker and incorproated into this process'
                # process_registry.
                 
        # END of the for idx loop
        # outer for idx loop ends and close the ssh connection if it has successfuly completed all commands execution

        ssh.close()
        transport = ssh.get_transport()
        if transport:
            transport.close()




        #debug for patch7c
        print(f"[TRACE][install_tomcat] Reached successful registry update step for {ip}")


        # This is patch1:  ✅ Log registry entry for successful installs. This prevents empty registry entries (successes) 
        # from creating a resurrection log. This will ensure that all installation threads leave some sort
        # of registry fingerprint unless they are legitimate early thread failures.
       



        ## Comment out this line as it is a blanket install_success for any exit out of the for idx loop ##
        #update_resurrection_registry(ip, attempt=0, status="install_success", pid=multiprocessing.current_process().pid)



        # For patch7c: Thread-local tagging block (add this right after update_resurrection_registry)
        # This is part of the code  necesary for the patch7c in resurrection_monitor_patch7c() function. 
        # This creates a thread_registry for the current ip and since this part of the code is"install_success" the thread
        # entry is configured as such for status.  To make the thread registry persist through multiple calls of the install_tomcat
        # which threaded_install() will do per process if multiple threads in the process, we need additional code as well

        ## NOTES: This snippet only handles a single IP **per thread**. To persist across all IPs (i.e. multiple calls to `install_tomcat()`), the `registry_entry` needs to live outside the function — ideally as a **shared mutable dict** owned by `threaded_install()`
        ## so we need to return this registry_entry to the calling function threaded_install.
        ## If keeping `registry_entry` local to this function, it will be recreated for every call. Which is what we need.
        ## Create it fresh for each new thread/IP and then return it to threaded_install for adding to the thread_registry which
        ## will eventuall be called the process_registry in the tomcat_worker that calls threaded_install


        # install_success only after the for idx iterates through all commands successfully (no failure or stubs hit), at
        # which time, exit the for idx and create registry below:
        registry_entry = {    
            "status": "install_success",
            "attempt": 0,
            "timestamp": str(datetime.utcnow()),
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "tags": ["install_success", "installation_tomcat_completed"]
        }



        ##### Get rid of this code block as part of legacy code that we no longer need
        ##### successful_regsitry_ips is done in aggregate main() code and at the process level in resurrection_monitor_patch7d
        ### Debugging code to track down the successful_registry_ips tagging issue
        ## 🔍 Trace log to confirm registry tagging per thread
        #try:
        #    registry_snapshot = dict(resurrection_registry)  # shallow copy under lock-less read
        #    pid = multiprocessing.current_process().pid

        #    print(f"[TRACE] ✅ Tagging success for IP {ip} | PID {pid}")
        #    print(f"[TRACE] Registry BEFORE update: {registry_snapshot.get(ip, 'Not present')}")

        #except Exception as e:
        #    print(f"[TRACE ERROR] Snapshot read failed for {ip} | PID {pid} — {e}")




        # debug for patch7c 
        print(f"[TRACE][install_tomcat] Returning install result for {ip}")

        print(f"Installation completed on {ip}")

        # make sure to return this registry_entry for this thread instance to threaded_install
        return ip, private_ip, registry_entry




   
        ### Remove this as this is for the try block above, that is causing many issues.

        ## This is the exception block. Tag the thread with the stub_created_after_exception. This will be categorized
        ## as a failed_registry_ips and not missing_registry_ips. Missing is only for true ghosts that have no pid.
        ## An exception has a PID and an IP address. This thread can potentially be resurrected.
        #
        #except Exception as e:
        #    print(f"[ERROR][install_tomcat] Exception occurred for {ip}: {e}")
        #    registry_entry = {
        #        "status": "stub_created_after_exception",
        #        "attempt": 0,
        #        "timestamp": str(datetime.utcnow()),
        #        "pid": multiprocessing.current_process().pid,
        #        "thread_id": threading.get_ident(),
        #        "thread_uuid": thread_uuid,
        #        "public_ip": ip,
        #        "private_ip": None,
        #        "tags": ["ghost_post_pid", "stub"],
        #        "error": str(e)
        #    }
        #    return ip, None, registry_entry

    ##### END OF install_tomcat() function ends here ######






    

    # MOVED THIS BLOCK TO ABOVE
    ### added this because when running this as a module getting an error that there are no public ips on the instances
    ## I did check and the instances did have public ips.
    ## Ensure public_ips is not empty before creating ThreadPoolExecutor
    #if not public_ips:
    #    print("No public IPs found. Exiting.")
    #    sys.exit(1)
    #




    # Use ThreadPoolExecutor to run installations in parallel
    # In this updated script, the `install_tomcat` function returns a tuple containing the IP address and the result (`True` for success, `False` for failure). The script collects the IP addresses of both successful and failed installations in separate lists (`successful_ips` and `failed_ips`) and prints them out at the end. This way, you can easily identify which instances had successful installations and which ones failed.
    # Also: This script now correctly checks for both SSH connection failures and package installation failures, and prints out the IP addresses of both successful and failed installations.
    # This is to troubleshoot an issue where with 50 instances there were 2 that did not have Installation completed.

    failed_ips = []
    successful_ips = []
    failed_private_ips = []
    successful_private_ips = []

   # HERE IS THE MAIN CHANGE FOR THE multiprocessing optmization. First we are going to tie the thread pools
   # to the number of cores (the VPS has 6 CPU cores).  Each ThreadPoolExecutor will have max workers of 6 at a time.
   # Previously we had max_workers set to length of public_ips which is 50. This is creating a lot of contention with only
   # 6 cores and a lot of context switching.    To optimize this first we will restrict this to the os.cpu_count of 6
   # This means that there will be 6 threads at the same time. To further optimize this with main() function below, we 
   # will also start 6 processes defined by num_processes=os.cpu.count (6 as well.  Each process wil invoke the 
   # install_tomcat_on_instances function running the 6 ThreadPoolExecutor threads on its dedicated core.   Thus there
   # are on average 6 threads running on a process on each of the 6 cores, for 36 concurrent SSH tomcat installations
   # at any time. This will reduce the contention of just running ThreadPoolExecutor with all 50 threads randomly assigned
   # across the cores which created a lot of context switching. NOTE that chunk size is another variable. See main() below
   # Chunk size is the chunk of ips that are grabbed by each process. So if 50 ip addresses each of the 6 processes will
   # get 8 ip addresses, and each process can use the 6 threads in the process to process the SSH connections.  In this
   # case 6 ips processed immediately and then the other 2 when some of the 6 threads are done with the initial 6 ips.
   # however need additionl logic because with 50 instances and 6 processes there are 2 "orphaned" ips that need to be
   # dealt with. This requires additional logic.







#### COMMENT OUT THIS ENTIRE BLOCK and REPLACE with a Benchmarking wrapper below. The code below is the exact same
#### but just wrapped in benchmarking code for the multi-threading
#
### USE instance_info instead of instance_ips within tomcat_worker for the pooling mulit-processing
#    with ThreadPoolExecutor(max_workers=max_workers) as executor:
#        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_info]
#
#
#
### comment out this next block temporarily to disable multi-threading completely
#### USE THIS for the non-pooling multi-processing case
##    with ThreadPoolExecutor(max_workers=max_workers) as executor:
##        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]
##
#
#
#
## with max_workers = 6
##    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
##        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]
#
#
## with max_workers=50
#   #with ThreadPoolExecutor(max_workers=len(public_ips)) as executor:
#        #futures = [executor.submit(install_tomcat, ip, private_ip, instance_id) for ip, private_ip, instance_id in zip(public_ips, private_ips, instance_ids)]
#        
#
#        for future in as_completed(futures):
#            ip, private_ip, result = future.result()
#            if result:
#                successful_ips.append(ip)
#                successful_private_ips.append(private_ip)
#            else:
#                failed_ips.append(ip)
#                failed_private_ips.append(private_ip)
#









    ### This is the wrapped multi-threading code for benchmarking statistics
    ### Make sure to indent this within the tomcat_worker function!
    #def threaded_install():
        
    ## For patch7d of resurrection_monitor add the args to the threaded install function. This is not absolutely required
    ## since threaded_install and install_tomcat are both inside of tomcat_worker which has these 2 args but adding it
    ## for clarity sake. instance_info or chunk or assigned_ips is required for per process ghost detection.
    def threaded_install(instance_info, max_workers):



        import uuid # This is for adding uuid to the logs. See below

        thread_registry = {}  # Shared across threads in this process. This is required to collect all ips in the thread
        # We will use this for patch 7c to the resurrection_monitor_patch7c function.  The tags will be collated in that function
        # at the thread level.


        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_info]

#            for future in as_completed(futures):
#                ip, private_ip, result = future.result()
#                if result:
#                    successful_ips.append(ip)
#                    successful_private_ips.append(private_ip)
#                else:
#                    failed_ips.append(ip)
#                    failed_private_ips.append(private_ip)

### Add ip visiblity for troubleshooting the EC2 instances to pid in logs for resurrection code:
#            for future in as_completed(futures):
#                ip, private_ip, result = future.result()
#                pid = multiprocessing.current_process().pid
#
#                if result:
#                    logging.info(f"[PID {pid}] ✅ Install succeeded | Public IP: {ip} | Private IP: {private_ip}")
#                    successful_ips.append(ip)
#                    successful_private_ips.append(private_ip)
#                else:
#                    logging.info(f"[PID {pid}] ❌ Install failed | Public IP: {ip} | Private IP: {private_ip}")
#                    failed_ips.append(ip)
#                    failed_private_ips.append(private_ip)




## Add uuid since the pids are reused in hyper-scaling. This is not absolutely required as my log files do use
## uuid to differentiation same pid benchmark logs but adding to content of the logs will help in the future
## for logging forenscis
## install_tomcat invoked by the ThreadPoolExecutor will return registry_entry as the result
## So assign future.result() from install_tomcat to registry_entry, the current thread's registry entry

            ##### this has the threaded_install() stub registry logic for protection against catostrophic failures
            ##### in install_tomcat. These failures will now genearte a stub registry for reliable forensics and tracking

            for future in as_completed(futures):
                try:
                    ip, private_ip, registry_entry = future.result()
                    pid = multiprocessing.current_process().pid

                    if registry_entry and "thread_uuid" in registry_entry:
                        thread_registry[registry_entry["thread_uuid"]] = registry_entry
                        thread_uuid = registry_entry["thread_uuid"]

                    else:
                        # Silent failure — no registry returned. This will catch slient failures that occur either in
                        # the ssh.connect loop or the for attemp loop (installing tomcat) of install_tomcat, where the 
                        # code flow returns back from install_tomcat to threaded_install(This function).
                        pid = multiprocessing.current_process().pid
                        if pid:
                            stub_uuid = uuid.uuid4().hex[:8]
                            stub_entry = {
                                "status": "stub",
                                "attempt": -1,
                                "pid": pid,
                                "thread_id": threading.get_ident(),
                                "thread_uuid": stub_uuid,
                                "public_ip": ip,
                                "private_ip": private_ip,
                                "timestamp": str(datetime.utcnow()),
                                "tags": ["stub", "silent_abort", "no_registry"]
                            }
                            thread_registry[stub_uuid] = stub_entry
                            thread_uuid = stub_uuid  # For logging below
                            registry_entry = stub_entry  # So status and IPs can be logged

                    # Logging and IP tracking
                    status = registry_entry["status"] if "status" in registry_entry else "undefined"
                    pid = registry_entry.get("pid", "N/A")

                    if status == "install_success":
                        logging.info(f"[PID {pid}] [UUID {thread_uuid}] ✅ Install succeeded | Public IP: {ip} | Private IP: {private_ip}")
                        successful_ips.append(ip)
                        successful_private_ips.append(private_ip)
                    else:
                        logging.info(f"[PID {pid}] [UUID {thread_uuid}] ❌ Install failed | Public IP: {ip} | Private IP: {private_ip}")
                        failed_ips.append(ip)
                        failed_private_ips.append(private_ip)
                #### try block ends here #####

                except Exception as e:
                    print(f"[ERROR][threaded_install] Future failed: {e}")








            ######### Replaced this  block below with the one above to incorporate stub registry in catostropic exist
            #########  from install_tomcat(). We have seen this happen before, but very infrequently and only under hyper-
            ########  scaling of processes

            #for future in as_completed(futures):
            #    #ip, private_ip, result = future.result()
            #    ip, private_ip, registry_entry = future.result()
            #    pid = multiprocessing.current_process().pid
            #    
            #    ## get rid of this and use the install_tomcat thread_uuid as definitive source.
            #    #thread_uuid = uuid.uuid4().hex[:8]

            #    # Updated for patch7c
            #    # registry_entry. This is built in the install_tomcat() 
            #    # This is a single thread/ip entry that is used to build up the process thread_registry
            #    # which will end up with all the ips in the process once all threads have been executed in the process
            #    # thread_registry is built up with index thread_uuid to ensure it is totally unique. This will be the 
            #    # current registry_entry and this is added to it for each thread executed by the ThreadPoolExecutor called by
            #    # the current process running threaded_install

            #    # add thread_uuid to the registry_entry and keeping IPs inside the entry helps make logs easier to parse later — 
            #    #especially if UUIDs are opaque.
            #    # this is now from the install_tomcat the definitive source
            #    # install_tomcat is called by ThreadPoolExecutor above and will return its thread_uuid in the registry 
            #    # for threaded_install(this function) to consume. 
            #    #registry_entry["thread_uuid"] = thread_uuid
            #    
            #    #registry_entry["public_ip"] = ip
            #    #registry_entry["private_ip"] = private_ip

            #    # Store in registry keyed by IP or UUID. This keeps them uniqe regardless of pid reuse.
            #    # For multi-threaded multi-processed registry entries keying by thread_uuid is best.
            #    # thre thread_registry will be built up with all thread registry entries for per process and returned to the
            #    # calling function of threaded_install which is tomcat worker. Tomcat_worker will assign this to process_registry
            #    # retgistry_entry is returned from install_tomcat to this function, threaded_install
            #    #thread_registry[thread_uuid] = registry_entry
            #    thread_registry[registry_entry["thread_uuid"]] = registry_entry


            #    # Keep the logging as before
            #    # we need to catch if registry has corruption 
            #    # Try to retrieve the value for `'status'` from `registry_entry`. If it’s missing (not set, or the whole entry 
            #    # is malformed), then default to the string `'undefined'`.”  That way it will fall into the else and we can see  it
            #    # logged as Install failed for further forensic thread investigation.
            #    status = registry_entry.get("status", "undefined")
            #    


            #    # insert this for thread_uuid usage in logging
            #    thread_uuid = registry_entry["thread_uuid"]


            #    if registry_entry.get("status") == "install_success":
            #    #if registry_entry:
            #        logging.info(f"[PID {pid}] [UUID {thread_uuid}] ✅ Install succeeded | Public IP: {ip} | Private IP: {private_ip}")
            #        successful_ips.append(ip)
            #        successful_private_ips.append(private_ip)
            #    else:
            #        logging.info(f"[PID {pid}] [UUID {thread_uuid}] ❌ Install failed | Public IP: {ip} | Private IP: {private_ip}")
            #        failed_ips.append(ip)
            #        failed_private_ips.append(private_ip)




        # debugs for the patch7c issue with process_registry
        # this should print all the thread ip registry entries for this pid by uuid (which will be unique across all processes)
        print(f"[TRACE][threaded_install] Final thread_registry contains {len(thread_registry)} entries")
        
#        for uuid_key, registry_entry in thread_registry.items():
#            print(f"[TRACE][threaded_install] UUID {uuid_key}: {registry_entry}")

        for uuid_key, registry_entry in thread_registry.items():
            pid = registry_entry.get("pid", "N/A")
            print(f"[TRACE][threaded_install] UUID {uuid_key} | PID {pid}: {registry_entry}")



        return thread_registry  # Add this return line. This is very important. This is so that the run_test, which calls
        # threaded_install gets back the thread_registry which is the list of IPs processed by the current process, in a registry
        # This will be defined as process_registry which will then be passed to the patch7c resurrection_monitor_patch7c()
        # function so that the registry IP values and tags (treads) can be collated for artfact publishing (failled, successful, etc)


    ### END OF threaded_install() #####





    ### The run_test is defined outside of the function at the top of this module.  The run_test will in turn call benchmark
    ### function to run the specific benchmarks on the multi-threading ThreadPoolExecutor that the process is executing on
    ### the chunk of chunk_size
    ### the run_test is not indented inside of tomcat_worker function!
    
    #run_test("Tomcat Installation Threaded", threaded_install)
   


    ## debug prints for run_test call to threaded_install for patch7c
    print(f"[TRACE][tomcat_worker] Preparing to invoke threaded_install via run_test")
    print(f"[TRACE][tomcat_worker] Instance count for this chunk: {len(instance_info)}")



    ## THIS NEEDS to be modifed for the patch7c multi-threading registry 
    ## threaded_install now returns the thread_registry (list of all IPs in the process as a process registry)
    ## Assign this thread_registry the name process_registry. This will later be passed to the new resurrection_monitor_patch7c
    ## for collating and tag processing
    ## NOTE that run_test needs to be slightly modified to return the thread_registry from threaded_install so that it can be
    ## assigned to the process_registry

    #process_registry = run_test("Tomcat Installation Threaded", threaded_install)

    # For resurrection_monitor_patch7d need to pass instance_info and max_workers because i have chnaged the 
    # def threaded_install from threaded_install() to def threaded_install(instance_info, max_workers). Another option
    # is to revert back to threaded_install() and then the change below is not required. I will use the args for clarity.
    process_registry = run_test("Tomcat Installation Threaded", threaded_install, instance_info, max_workers)


    ## debug prints for run_test call to threaded_install which returns thread_registry which is assigned to process_registry
    ## This is for patch7c testing
    print(f"[TRACE][tomcat_worker] Process registry returned with {len(process_registry)} entries")
    for ip, data in process_registry.items():
        print(f"[TRACE][tomcat_worker] Registry entry [{ip}]: {data}")



#    ## --- COMMENTED OUT FOR DISK-HANDOFF write-to-disk WORKFLOW ---
#    ## There is a problem with all_process_registries. It is NOT shared between isolated process memory and need to do a 
#    ## write-to-disk approach.
#    ##
#    ## This is the aggregator code. This will aggregate the process level registry(process_registry) to all_process_registries
#    ## all_process_registries will then be fed into aggregate_process_registries global function to flatten it out to a dict
#    ## of thread registry entires (abstracted from processes). This will result in final_registry which is used to create the
#    ## final_aggregate_execution_run_registry.json for the complete runtime registry status(tags) of all the threads that were
#    ## run in the execution run. final_registry will also be fed into summarize_registry global function to create stats and classify
#    ## the thread registry values as successful, failed, total = successful + failed and missing (delta between benchmark_ips_artifact.log
#    ## and total.  benchmark_ips_artifact.log is the golden standard from the main and process orchestration layer and will have 
#    ## every single IP (thread) that was created (except for very rare circumstances with AWS EC2 instances; these will be dealt
#    ## with later.
#
#    import copy
#    all_process_registries.append(copy.deepcopy(process_registry))
#


## write-to-disk aggregator code in tomcat_worker
## This writes the current process call on tomcat_worker process_registry to disk and saves it as
## "/aws_EC2/logs/process_registry_{pid}_{tag}.json". This will later be aggregated with the other process process_registry in main()
## as "/aws_EC2/logs/final_aggregate_execution_run_registry.json"
## make sure to import multiprocessing, json, os at top of this module.

    os.makedirs("/aws_EC2/logs", exist_ok=True)                # ensure directory exists 
    pid = multiprocessing.current_process().pid
    tag = uuid.uuid4().hex[:8]
    out = f"/aws_EC2/logs/process_registry_{pid}_{tag}.json"
    with open(out, "w") as f:
        json.dump(process_registry, f, indent=2)
    print(f"[TRACE] Wrote process registry to {out}")







    ### Add the verification of the location of the benchmark file location on the container
    # Print the contents of `/aws_EC2/logs`. The filename will be unique tagged with the pid of the process for
    # each process
    print("PER PROCESS Contents of /aws_EC2/logs:")
    print(os.listdir("/aws_EC2/logs"))





    if successful_ips:
        print(f"Installation succeeded on the following IPs: {', '.join(successful_ips)}")
        print(f"Installation succeeded on the following private IPs: {', '.join(successful_private_ips)}")
    if failed_ips:
        print(f"Installation failed on the following IPs: {', '.join(failed_ips)}")
        print(f"Installation failed on the following private IPs: {', '.join(failed_private_ips)}")

    print("ThreadPoolExecutor script execution completed.")






###### Call the resurrection monitor function. This is run per process. So if 5 threads in a process it the resurrection registry
###### will have scanned for 5 EC2 instance installs and logged any that have failed 2 watchdog attempts. These are resurrection
###### candidates. The monitor will create the log for the process and list those threads. Thus for 450 processes with 1 thread each
###### for example, there will be 450 of these log files. Will aggregate them later.  This is the end of the tomcat_worker() function:
           

    # resurrection_monitor()
    
    # replace resurrection_monitor() with resurrection_monitor_patch7c() for migration to patch7c
    #resurrection_monitor_patch7c()


    ## debugs for process_registry above for patch7c testing
    print(f"[TRACE][tomcat_worker] Passing process_registry to resurrection_monitor with {len(process_registry)} entries")


    # add the process_registry (see above) which is the registry of the multi-threading process IPs. This is from threaded_install
    # which now returns the thread_registry which is the process_registry. Will have to update the resurrection monitor to
    # accept the process_registry
    
    #resurrection_monitor_patch7d(process_registry)


    ##### patch7d: add the argument chunk which is instance_info which will be assigned_ips in the resurrection_monitor_patch7d
    ##### function. This is required so that we have a GOLD ip list of what should be processed by the thread in the process
    ##### Real time process_registry entries missing from that list of ips are ghosts.
    ##### After `threaded_install()` returns `process_registry`, pass both `process_registry` and `instance_info` 
    ##### (which is the assigned chunk) to the monitor:

    #resurrection_monitor_patch7d(process_registry, instance_info)

    ##### replacing resurrection_monitor_patch7d with resurrection_monitor_patch8
    resurrection_monitor_patch8(process_registry, instance_info)

    # use the run_resurrection_monitor_diag() function to troublshoot the issues in resurrection_monitor_patch7c
    #run_resurrection_monitor_diag(process_registry)




##### END OF tomcat_worker() function ######
# tomcat_worker() calls threaded_install() which calls install_tomcat(). Both threaded_install and install_tomcat are defined in
# tomcat_worker












#### main() level code and helper functions::
###########################################################################################################

#### ADD the main() level process and process pooling orchestration logging level code. The setup helper function is beow
#### The function is incorporated in the main() function
#### This is using the same log_path as used in the per process and threading log level code. /aws_EC2/logs is a mapped
#### volume in the docker container to the project archive directory on the gitlab pipeline repo.  This is the line
#### from .gitlab-ci.yml file:
####     - docker run --rm --env-file .env -v $CI_PROJECT_DIR/logs:/aws_EC2/logs $CI_REGISTRY_IMAGE:latest
#### The logging in main() using this helper function will be logged to the gitlab pipeline console as well as a log file
#### in the archive directory for the pipeline
#### The file will be named /aws_EC2/logs/main_{pid}.log, in the same archive but separate from the process level logs.

def setup_main_logging():
    pid = multiprocessing.current_process().pid
    log_path = f'/aws_EC2/logs/main_{pid}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger("main_logger")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(process)d - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    # **Add Initial Swap Logging**
    swap_info = psutil.swap_memory()
    logger.info(f"[MAIN] Initial Swap Total: {swap_info.total / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Swap Used: {swap_info.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Swap Free: {swap_info.free / (1024**2):.2f} MB")

    return logger





## (helper logging function) this is for inter-test process orchestration level memory stats.
## What i have done is modularize the threading of these operations into a second function that follows(see below
## this function).
## This function is for the actual logging semantics and output structure

#def sample_inter_test_metrics(logger, delay, label):
#    """Samples memory and CPU metrics at specific points during execution."""
#    time.sleep(delay)  # Wait for the specified timing
#
#    mem = psutil.virtual_memory()
#    swap = psutil.swap_memory()
#    #cpu_usage = psutil.cpu_percent(interval=None, percpu=True)
#
#    cpu_usage = psutil.cpu_percent(interval=1, percpu=True)
#    
#    logger.info(f"[MAIN] {label} Inter-test RAM Usage: {mem.used / (1024**2):.2f} MB")
#    logger.info(f"[MAIN] {label} Inter-test Free Memory: {mem.available / (1024**2):.2f} MB")
#    logger.info(f"[MAIN] {label} Inter-test Swap Usage: {swap.used / (1024**2):.2f} MB")
#    logger.info(f"[MAIN] {label} Inter-test CPU Usage (per-core): {cpu_usage}")

## Update the sample_inter_test_metrics helper function with swap stats
def sample_inter_test_metrics(logger, delay, label):
    """Samples memory, CPU, and swap metrics at specific points during execution."""
    time.sleep(delay)

    # Capture memory, swap, and CPU usage
    # NOTE for cpu need interval set to 1 to get reliable core stats inter-test. Interval 0 was not working.
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu_usage = psutil.cpu_percent(interval=1, percpu=True)

    # NEW: Capture swap percentage usage
    swap_percent = (swap.used / swap.total) * 100 if swap.total > 0 else 0

    # Log RAM, CPU, and enhanced swap stats
    logger.info(f"[MAIN] {label} Inter-test RAM Usage: {mem.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Free Memory: {mem.available / (1024**2):.2f} MB")

    logger.info(f"[MAIN] {label} Inter-test Swap Usage: {swap.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Swap Free: {swap.free / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Swap Percentage Used: {swap_percent:.2f}%")

    logger.info(f"[MAIN] {label} Inter-test CPU Usage (per-core): {cpu_usage}")

    # NEW: Capture swap file details from `swapon -s` (Linux only)
    try:
        with open('/proc/swaps', 'r') as f:
            swap_details = f.readlines()[1:]  # Skip header line
            logger.info(f"[MAIN] {label} Swap File Details: {''.join(swap_details).strip()}")
    except FileNotFoundError:
        logger.warning(f"[MAIN] {label} Swap file details unavailable (not a Linux system).")





## (helper logging function) call this function in the middle of the logging in main() to create a new and independent 
## thread in the background for each thread metric variant
## The objective is to collect load bearing memory and CPU stats for the hyper-scaling tests
## moving the threading.Thread method outside of main() makes this much more extensible in case I need to add more
## static or dynamic sampling points!!
## NOTE: i forgot to add the thread storage so that we can wait for them to complete in main with .join!
## The start_inter_test_logging returns a list of threads so that main() can ensure that they are all joined prior to closing and
## flushing. This ensures all logging stats have been collected.

def start_inter_test_logging(logger, total_estimated_runtime):
    """Launch separate logging threads and return them for later joining."""
    threads = []  # Store threads for later synchronization

    random_delay = random.uniform(0.3, 0.7) * total_estimated_runtime  # Random 30-70%
    fixed_50_delay = 0.5 * total_estimated_runtime  # Fixed 50%
    fixed_75_delay = 0.75 * total_estimated_runtime  # Fixed 75%

    # Start each thread and store it
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, random_delay, "Random 30/70")))
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, fixed_50_delay, "50%")))
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, fixed_75_delay, "75%")))

    # Get this list of threads aboe and start them. Grouping them into a list makes this easy to do the .join in
    # main() assuring logging is all complete prior to flush and closing things out in main()
    for thread in threads:
        thread.start()

    return threads  # Return the list of threads to be joined in main()






## (helper logging function)  call this function in the middle of the logging in main() right after the call to start_inter_test_logging
## This is very similar in approach, but start the thread for this from main() rather than from the helper function below
## We don't need the extensibility of the start_inter_test_logging just to monitor the kswapd0

#def sample_kswapd_cpu_main(stop_event, logger, interval=60):
#    logger.info("[DEBUG] kswapd monitoring thread loop is running...")
#
#    while not stop_event.is_set():
#        kswapd_cpu = next((p.cpu_percent(interval=None) for p in psutil.process_iter(attrs=['name']) if 'kswapd0' in p.info['name']), None)
#        if kswapd_cpu is not None:
#            logger.info(f"[MAIN] kswapd0 CPU usage: {kswapd_cpu:.2f}%")
#        stop_event.wait(interval)
## Comment out the kswapd logging stuff. psutil has no access to process level stuff on the host VPS (sytem stuff like CPU, RAM, swap
## is ok, but no process level stuff works. Have to run that in separate python script venv on the VPS host itself.






########################################################################################################################
#### REFACTORED main() to support multi-processing with pooling to deal with hyperscaling case
#### note that this is still based upon Model 2 from the original main() below that does not have the pooling with
#### the multiprocessing
####
#### with model 2: each process handles chunk_size of IPs with max_workers number of threads. Any extra IPs use
#### an additional process.
####
#### This main() uses the tomcat_worker rather than the original install_tomcat_on_instances used in the main() 
#### without pooling.   The tomcat_worker permits pickling by main().   
####
#### The pooling will start the desired_count of concurrent processes (25 has been tested for error free)
#### The rest of the processes will be initiated as the original 25 finish up their tasks and exit, one by one
#### with multiprocessing.Pool(processes=desired_count) as pool:
#### from extensive testing it is recommended to keep desired_count to 25 for this pariticular setup
####
#### The chunk_size is the number of IPs (dictionary list) assigned per process
####
#### max_workers is the number of threads in the ThreadPoolExecutor to use to parallel process the SSH connections for
#### the chunk dictionary list of IPs.  
####
#### chunk_size should always be less than or equal to max_workers. If oversubscribing max_workers performance degrades
#### very raplidly.  Unused threads (undersubscrbing, with chunk_size < max_workers) does not degrade performance.
####
#### chunk is the actual dictionary list of IPs to be processed per process
####
#### chunks is the dictionary list of all of the IPs to be processed (the total len(instance_ips) of IPs)
#### chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
#### chunks is required to track the entire list of all the IPs because the desired_count cannot process them all
#### in parallel initially and has to take up the extras serially as the pool of processes free up, one by one.
####
#### args_list is the List of args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]  passed to the tomcat_worker function above
#### using the pool.starmap pool.starmap(tomcat_worker, args_list) to assign the chunk blocks to each successive
#### process running in parallel (initially the desired_count of processes)
####
#### the configurable options are chunk_size, max_workers (like with model2) and desired_count
#### The total number of EC2 instances are specified in the .gitlab-ci.yml and passed and env variables to the first
#### python module in the python package for this project (11 modules so far)
####

def main():
    load_dotenv()


# The helper function setup_main_logging for the logging at the process orchestration level, see below
# Pass this logger into the inter-test helper function call below sample_inter_test_metrics 
    logger = setup_main_logging()


# Define the total_estimated_runtime as global so that it can be used in the call to start_inter_test_logging
# call in main() for the inter-test metrics.  We will use a 0.30-0.70 randomizer and static points on this total_estimated_value 
# in which to take the sample. From previous hyper-scaling of processes 10 minutes is a good baseline for these types of tests.
    global total_estimated_runtime
    total_estimated_runtime = 600  # Adjust based on previous test execution times






    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("region_name")

    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    my_ec2 = session.client('ec2')

    exclude_instance_id = 'i-0aaaa1aa8907a9b78'
    print(f"exclude_instance_id: {exclude_instance_id}")

    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
    instance_ids = [
        instance['InstanceId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        if instance['InstanceId'] != exclude_instance_id
    ]

#    while True:
#        response_statuses = {'InstanceStatuses': describe_instances_in_batches(my_ec2, instance_ids)}
#        all_running = all(instance['InstanceState']['Name'] == 'running' for instance in response_statuses['InstanceStatuses'])
#        if all_running:
#            break
#        print("Waiting for all instances to be in running state...")
#        time.sleep(10)

## Okay seeing a very very strange AWS API issue with this describe_instances_in_batches method whereby the instances in AWS console
## are indicating running but the state may still be in pending on the API. Not quite sure what is going on, but python code in 
## original while True loop above getting stuck in Waiting for all instances to be in running state.

    while True:
        response_statuses = {'InstanceStatuses': describe_instances_in_batches(my_ec2, instance_ids)}

        for instance in response_statuses['InstanceStatuses']:
            instance_id = instance['InstanceId']
            state = instance['InstanceState']['Name']
            system_status = instance['SystemStatus']['Status']
            instance_status_check = instance['InstanceStatus']['Status']

            print(f"[DEBUG] Instance {instance_id} -> State: {state}, SystemStatus: {system_status}, InstanceStatus: {instance_status_check}")

        all_running = all(instance['InstanceState']['Name'] == 'running' for instance in response_statuses['InstanceStatuses'])

        if all_running:
            break

        print("Waiting for all instances to be in running state...")
        time.sleep(10)




    try:
        # make sure to change timeout 120 to 180 for t2.micro when using high process count (i.e, like 512)
        
        #instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, exclude_instance_id=exclude_instance_id, timeout=180)
        

        # The new wrapper around wait_for_all_public_ips as AWS is doing batch processing on large EC2 instance launches and
        # the code needs to wait for all the instances to be present and then poll and loop for all public ips to be present
        # the new functions are orchestarte_instance_launch_and_ip_polling and wait_for_instance_visiblilty (default timeout is
        # 180 seconds)
        instance_ips = orchestrate_instance_launch_and_ip_polling(exclude_instance_id=exclude_instance_id)

    except TimeoutError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print("[DEBUG] instance_ips initialized with", len(instance_ips), "entries")

    null_ips = [ip for ip in instance_ips if 'PublicIpAddress' not in ip or not ip['PublicIpAddress']]
    print(f"[DEBUG] Null or missing IPs: {null_ips}")

    expected_count = len(instance_ids)
    actual_count = len(instance_ips)
    if actual_count != expected_count:
        print(f"[WARNING] Expected {expected_count} IPs but got {actual_count}")

    if not any(ip['PublicIpAddress'] for ip in instance_ips):
        print("No public IPs found. Exiting.")
        sys.exit(1)

    security_group_ids = [
        sg['GroupId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        for sg in instance['SecurityGroups']
        if instance['InstanceId'] != exclude_instance_id
    ]

    ### Configurable parameters
    chunk_size = 2  # Number of IPs per process
    max_workers = 2 # Threads per process
    desired_count = 6 # Max concurrent processes (NOT threads) for iniital batch.
    #### For the 16 node test chunk_size of 2, max_workers of 2, and desired_count of 6 so that 2 processes are pooled for the
    #### last 4 of 16 nodes
    #### For the 512 test, it is one thread per process, so: chunk_size of 1, max_workers of 1, desired_count of 487 so that 
    #### 25 processes are pooled for the last 25 of the 512 nodes.

    chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]


    ######  aggregate gold ips from chunks  #########
    ######  Call to helper function hydrate_aggregate_chunk_gold_ip_list() to create a gold ip list of the 
    ######  AWS control plane list of IPs for the execution run. Later below the ghost detection logic will
    ######  use this GOLD list to compare to the aggregate registry for ghost thread detection. 
    ######  A ghost is defined as a thread that does not have a registry entry and thus no failure status tag
    ######  A ghost usually will not even have an assigned PID, thus it cannot have a registry entry to track it
    ######  The helper function returns gold_ips assigned to aggregate_gold_ips

    log_dir = "/aws_EC2/logs"
    aggregate_gold_ips = hydrate_aggregate_chunk_gold_ip_list(chunks, log_dir)

    print("[TRACE][aggregator] Aggregate GOLD IPs from chunk hydration:")
    for ip in sorted(aggregate_gold_ips):
        print(f"  {ip}")
    print(f"[TRACE][aggregator] Total GOLD IPs: {len(aggregate_gold_ips)}")



    # ADD this for the pooling level logging in main() that uses setup_main_logging() helper function
    total_processes = len(chunks)
    remaining = total_processes - desired_count
    pooled_batches = (remaining + desired_count - 1) // desired_count if remaining > 0 else 0
    # this uses ceiling division. for example 200 processes with desired_count 75 is (125+75-1)//75 =
    # 199/75 = round down(2.65)= 2 additional batches of the 75 max will cover the remaining 125 pooled processes

    logger.info(f"[MAIN] Total processes: {total_processes}")
    logger.info(f"[MAIN] Initial batch (desired_count): {desired_count}")
    logger.info(f"[MAIN] Remaining processes to pool: {remaining}")
    logger.info(f"[MAIN] Number of batches of the pooled processes. This is the *additional waves of processes that will be needed after the initial batch (`desired_count`) to complete all the work: {pooled_batches}")




    # [DEBUG] Show chunk details
    for i, chunk in enumerate(chunks):
        print(f"[DEBUG] Process {i}: chunk size = {len(chunk)}")
        print(f"[DEBUG] Process {i}: IPs = {[ip['PublicIpAddress'] for ip in chunk]}")

    
    args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]

    # call to the multiprocessing.Pool which calls tomcat_worker function above to process the chunk data of IPs with
    # max_workker threads. chunk_size number of IPs will be in the chunk passed to tomcat_worker
    
#    with multiprocessing.Pool(processes=desired_count) as pool:
#        pool.starmap(tomcat_worker, args_list)
#


#    # wrap the tomcat_worker in the tomcat_worker_wrapper function (defined at top of file as helper) to fix
#    # the problem with the pooled/queued processes not getting their own log file for the multi-processing logging
#    # code
#
#    logger.info("[MAIN] Starting multiprocessing pool...")
#    with multiprocessing.Pool(processes=desired_count) as pool:
#        pool.starmap(tomcat_worker_wrapper, args_list)
#
#    logger.info("[MAIN] All chunks have been processed.")
#    logger.info(f"[MAIN] Total execution time for all chunks of chunk_size: {time.time() - start_time:.2f} seconds")



#    # use a try finally block to get teh execution time to log regardless of exceptions in multiprocessin.Pool call
#    logger.info("[MAIN] Starting multiprocessing pool...")
#    try:
#        with multiprocessing.Pool(processes=desired_count) as pool:
#            pool.starmap(tomcat_worker_wrapper, args_list)
#    finally:
#        total_time = time.time() - start_time
#        logger.info("[MAIN] All chunks have been processed.")
#        logger.info(f"[MAIN] Total execution time for all chunks of chunk_size: {total_time:.2f} seconds")
#
#        print("[INFO] All chunks have been processed.")
#
#        for handler in logger.handlers:
#            handler.flush()
#            handler.close()
#        logging.shutdown()
#


# The above still not working with execution time in the main log file. Try doing explicit flush and exit
# on the handler, and make sure do execution time log message after multiprocessing pool call and before the flush
# This fixed the issue. 
# Capture memory stats at the start of execution
    logger = logging.getLogger("main_logger")  # Explicitly name it to avoid conflicts
    logger.setLevel(logging.INFO)
    
    initial_mem = psutil.virtual_memory()
    initial_swap = psutil.swap_memory()
    initial_cpu_usage = psutil.cpu_percent(interval=1, percpu=True)  # Capture per-core CPU usage


    logger.info(f"[MAIN] Initial RAM Usage: {initial_mem.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Free Memory: {initial_mem.available / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Swap Usage: {initial_swap.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial CPU Usage (per-core): {initial_cpu_usage}")


    logger.info("[MAIN] Starting multiprocessing pool...")


    # Start background logging threads by calling the start_inter_test_logging helper function()
    # I have moved the threading logic outside of main() to make this more extensible and flexible if we need to
    # add more variations in the samples, namely the CPU which is tricky to track and varies quite a bit during 
    # execution. All of these threads are background threads in the main() process
    # This is so that the main() program flow is not interupted in any way.
    # This is an asynchronous design:
    # By starting the inter-test sampling asynchronously, the main multiprocessing workload proceeds uninterrupted, and the 
    # logging thread quietly waits until that thread's retirement interval is reached.
    # Then, in the `finally` block, use a join on the returned list from start_inter_test_logging to make sure all the
    # threaded data has been collected before flush and closing thing out in main()

    inter_test_threads = start_inter_test_logging(logger, total_estimated_runtime)
    


    # Start the background logging thread for the kswapd0 monitoring as well. This is also asyncrhonous and will run in the 
    # background as we proceed in main() to start the processes below to run the worker threads for each chunk of chunk_size
    # with multipprocessing.Pool 
    # This will run in parallel with the inter_test_threads for the other logging stats
    # The call is to sample_kswapd_cpu_main helper function defined above

#    stop_event = threading.Event()
#    kswapd_thread = threading.Thread(target=sample_kswapd_cpu_main, args=(stop_event, logger, 60))
#    kswapd_thread.start()
#    ## Add debug
#    logger.info("[DEBUG] kswapd0 monitoring thread started!")




    start_time = time.time()

    ##### CORE CALL TO THE WORKER THREADS tomcat_worker_wrapper. Wrapped for the process level logging!! ####
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
    finally:
        ### Insert the aggregator code here for the final aggregation in main() after the multiprocessing.Pool
        ### This ensures that the final aggregation file is completed only when all the processes have completed using 
        ### tomcat worker to process the threads. This includes the pooled processes done after the initial desired_Count pools are
        ### done






        ## ##  --- COMMENTED OUT FOR DISK-HANDOFF write-to-disk WORKFLOW ---
        ## TRACE on all_process_registries
        #if not all_process_registries:
        #    print("[TRACE] all_process_registries is empty in main()")
        #else:
        #    print(f"[TRACE] all_process_registries contents: {all_process_registries}")



        # ##  --- COMMENTED OUT FOR DISK-HANDOFF write-to-disk WORKFLOW ---
        # ## The main() based aggregator does not work because the global all_process_registries is not shared across process
        # ## memory so this does not work for m mulit-processing. Need to use write-to-disk implementation

        # # ✅ Place aggregation block here
        # final_registry = aggregate_process_registries(all_process_registries)
        # summary = summarize_registry(final_registry)

        # with open("/aws_EC2/logs/final_aggregate_execution_run_registry.json", "w") as f:
        #     json.dump(final_registry, f, indent=2)

        # print("[TRACE][aggregator] Final registry summary:")
        # for tag, count in summary.items():
        #     print(f"  {tag}: {count}")




        # write-to-disk code in main() to aggregate the per process JSON in tomcat_worker into registries
        # registries is then passed to write-to-disk aggregate_process_registries to flatten it out
        # this final_registry is then passed to summarize_registry to summarize the status(tags) of each thread registry item
        print("[TRACE][aggregator] Starting disk-based aggregation…")

        os.makedirs("/aws_EC2/logs", exist_ok=True)

        # 1. Load every per-process JSON that was created in tomcat_worker into registries
        registries = []
        for fname in os.listdir("/aws_EC2/logs"):
            if fname.startswith("process_registry_") and fname.endswith(".json"):
                path = os.path.join("/aws_EC2/logs", fname)
                with open(path) as f:
                    registries.append(json.load(f))

        # 2. Flatten (merge process registries into flat thread registries) & summarize registries using the call to 
        # aggregate_process_registries
        final_registry = aggregate_process_registries(registries)
        summary = summarize_registry(final_registry)

        # 3. Persist final_registry to final_aggregate_execution_run_registry.json (exported as artifact to gitlab pipeline) 
        # This is the merged master registry
        agg_path = "/aws_EC2/logs/final_aggregate_execution_run_registry.json"
        with open(agg_path, "w") as f:
            json.dump(final_registry, f, indent=2)
        print("[TRACE][aggregator] Wrote final JSON to", agg_path)

        # 4. Print summary counts by status/tag to the gitlab console
        print("[TRACE][aggregator] Final registry summary:")
        for tag, count in summary.items():
            print(f"  {tag}: {count}")

        ##### comment this out for aggregate gold ips from chunks implementation for GOLD standard ####
        ## 5. Load the benchmark IP list (gold standard to compare to). This is created in resurrection_monitor_patch7c() function
        #benchmark_ips = set()
        #with open("/aws_EC2/logs/benchmark_ips_artifact.log") as f:
        #    for line in f:
        #        ip = line.strip()
        #        if ip:
        #            benchmark_ips.add(ip)

        # 6. Build IP sets from final_registry statuses (final registry is the aggregate runtime list of all the threads with ip addresses)
        # Get the success_ips from the tag(status), get failed as total - success and get missing as benchmark_ips(gold) - total_ips
        total_ips   = {e["public_ip"] for e in final_registry.values()}
        success_ips = {
            e["public_ip"]
            for e in final_registry.values()
            if e.get("status") == "install_success"
        }
        failed_ips  = total_ips - success_ips
        #missing_ips = benchmark_ips - total_ips
        #### aggregate gold ips from chunks ####
        missing_ips = aggregate_gold_ips - total_ips



        # 7. Dump per-category artifact logs to gitlab console
        for name, ip_set in [
            ("total_registry_ips", total_ips),
            ("successful_registry_ips", success_ips),
            ("failed_registry_ips", failed_ips),
            ("missing_registry_ips", missing_ips),
        ]:
            path = f"/aws_EC2/logs/{name}_artifact.log"
            with open(path, "w") as f:
                for ip in sorted(ip_set):
                    f.write(ip + "\n")
            print(f"[TRACE][aggregator] Wrote {len(ip_set)} IPs to {path}")

        # 8. Dump resurrection candidates JSON (all non-success entries; i.e. failed = total - successful or !successful)
        # This is also done in resurrection_monitor_patch7c at the process level.
        ts = int(time.time())
        candidates = [
            entry
            for entry in final_registry.values()
            if entry.get("status") != "install_success"
        ]
        cand_path = f"/aws_EC2/logs/resurrection_candidates_registry_{ts}.json"
        with open(cand_path, "w") as f:
            json.dump(candidates, f, indent=2)
        print(f"[TRACE][aggregator] Wrote {len(candidates)} candidates to {cand_path}")

        # 9. Dump ghost/missing JSON (benchmark IPs never touched). By definition these are simply ips and not registry entries
        # since they have never been processed as threads (true ghosts). This is done in the resurrection_monitor_patch7c at
        # the process level
        
        ghosts = sorted(missing_ips)
        
        ghost_path = f"/aws_EC2/logs/resurrection_ghost_missing_{ts}.json"
        with open(ghost_path, "w") as f:
            json.dump(ghosts, f, indent=2)
        print(f"[TRACE][aggregator] Wrote {len(ghosts)} ghosts to {ghost_path}")


        ##### aggregate gold ips from chunks ####
        # 10. Dump ghost IPs to plain-text log format (for GitLab artifact visibility)
        ghost_log_path = f"/aws_EC2/logs/aggregate_ghost_summary.log"
        with open(ghost_log_path, "w") as f:
            for ip in ghosts:
                f.write(ip + "\n")
        print(f"[TRACE][aggregator] Wrote {len(ghosts)} ghosts to {ghost_log_path}")





        # timing and cleanup

        total_time = time.time() - start_time
        logger.info("[MAIN] All chunks have been processed.")
        logger.info(f"[MAIN] Total execution time for all chunks of chunk_size: {total_time:.2f} seconds")

        # Ensure the inter-test metrics thread that were started in start_inter_test_logging completes before exiting
        # At this point we have the inter-test log information captured!!!
        # Ensure ALL inter-test logging threads assinged to "inter_test_threads" (the list of threads returned from
        # the function, finish before cleanup
        for thread in inter_test_threads:
            thread.join()



        # Likewise, ensure that the kswapd_thread that was started with kswapd_thread above completes before exiting
        # There is only one thread here to join.
#        stop_event.set()
#        kswapd_thread.join()


        print("[INFO] All chunks have been processed.")

        # Capture memory stats after execution
        final_mem = psutil.virtual_memory()
        final_swap = psutil.swap_memory()
        final_cpu_usage = psutil.cpu_percent(interval=None, percpu=True)

        logger.info(f"[MAIN] Final RAM Usage: {final_mem.used / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final Free Memory: {final_mem.available / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final Swap Usage: {final_swap.used / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final CPU Usage (per-core): {final_cpu_usage}")



        # **New Explicit Log Flush Approach**
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.flush()
                handler.stream.flush()  # Ensure OS writes immediately
                os.fsync(handler.stream.fileno())  # Force disk write

        # Now shutdown logging AFTER flushing
        logging.shutdown()



if __name__ == "__main__":
    main()







##### ORIGINAL MAIN without pooling for the multi-processing. this runs great but has trouble with more than
##### 25 concurrent processes. For hyper-scaling cases where there are 100s of EC2 instances and chunk_size is
##### on the smaller size, need to use pooling to effectively handle this. Otherwise there will be instances that
##### silently fail tomcat installation.
#### Visual Block uncomment out the entire block if switching between the two. The code below does not do pooling
#### with the multi-processing. Note the preferred model for testing is Model 2 below

#
## MAIN function is the second change to integrate multi-processing with the multi-threading in the install_tomcat_on_instances 
## function above. Move a lot of the public ip verification code into this block as well out of the install_tomcat_on_instances
## function. When the master script invokes this module main is run first and will verify all the public_ips are up
## and then main() calls the install_tomcat_on_instances function in the domain of each of its 6 processes that it creates
#
#
#def main():
#    load_dotenv()
#
#    # Set variables from environment
#    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
#    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
#    region_name = os.getenv("region_name")
#
#    # Establish a session with AWS
#    session = boto3.Session(
#        aws_access_key_id=aws_access_key,
#        aws_secret_access_key=aws_secret_key,
#        region_name=region_name
#    )
#
#    # Create an EC2 client
#    my_ec2 = session.client('ec2')
#
#    # Define the instance ID to exclude (the EC2 controller)
#    exclude_instance_id = 'i-0aaaa1aa8907a9b78'
#    # Debugging: Print the value of exclude_instance_id
#    print(f"exclude_instance_id: {exclude_instance_id}")
#
#
#    # Describe the running instances (including pending)
#    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
#
#    # Get the instance IDs of the running instances except the excluded instance ID
#    instance_ids = [
#        instance['InstanceId']
#        for reservation in response['Reservations']
#        for instance in reservation['Instances']
#        if instance['InstanceId'] != exclude_instance_id
#    ]
#
#
#
#    # Wait for all instances to be in running state
#    while True:
#        ## this needs to use the describe_instances_in_batches helper function at the top of this file becasuse
#        ## i am hitting the llimit of 100 on the DescribeInstanceStatus method
#        ##response_statuses = my_ec2.describe_instance_status(InstanceIds=instance_ids)
#        
#        response_statuses = {'InstanceStatuses': describe_instances_in_batches(my_ec2, instance_ids)}
#
#        all_running = all(
#            instance['InstanceState']['Name'] == 'running'
#            for instance in response_statuses['InstanceStatuses']
#        )
#        if all_running:
#            break
#        print("Waiting for all instances to be in running state...")
#        time.sleep(10)
#
#
#
#
#
####  NEW1: REMOVE the 3 blocks below. Replace these with the new improved function call below for 
###   wait_for_all_public_ips
##    # NEW
##    # Add a delay to ensure public IPs are available before proceeding with the installation
##    print("Adding delay to ensure public IPs are available...")
##    time.sleep(40)
##
##
##    # Describe the running instances again to get updated information
##    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
##
##    # Get the public IP addresses and security group IDs of the running instances except the excluded instance ID
##    instance_ips = [
##        {
##            'InstanceId': instance['InstanceId'],
##            'PublicIpAddress': instance.get('PublicIpAddress'),
##            'PrivateIpAddress': instance.get('PrivateIpAddress')
##        }
##        for reservation in response['Reservations']
##        for instance in reservation['Instances']
##        if instance['InstanceId'] != exclude_instance_id
##    ]
##
#
#
#
#
#
#
###   NEW for main(): Replace the blocks above with this new code with the improved function call below
##    wait_for_all_public_ips 
##    # Now wait until all instances have public IPs
#
##    try:
##        instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, timeout=60)
##    except TimeoutError as e:
##        print(f"[ERROR] {e}")
##        return  # or handle the error appropriately
##
##    Note have added exclue_instance_id in definition of instance_ips from original code because we do not want to
##    install tomcat on the controller!!!
##
#    try:
#        instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, exclude_instance_id=exclude_instance_id, timeout=120)
#    except TimeoutError as e:
#        print(f"[ERROR] {e}")
#        sys.exit(1)
#
#
#
#
#
### DEBUGS for public ips
#
#    # add this debug as well for the model2 scope issue?????
#    print("[DEBUG] instance_ips initialized with", len(instance_ips), "entries")
#
#    # NEW
#    # After instance_ips is populated
#    null_ips = [ip for ip in instance_ips if 'PublicIpAddress' not in ip or not ip['PublicIpAddress']]
#    print(f"[DEBUG] Null or missing IPs: {null_ips}")
#
#    # NEW
#    expected_count = len(instance_ids)
#    actual_count = len(instance_ips)
#    if actual_count != expected_count:
#        print(f"[WARNING] Expected {expected_count} IPs but got {actual_count}")
#
#    # Ensure public_ips is not empty before proceeding
#    if not any(ip['PublicIpAddress'] for ip in instance_ips):
#        print("No public IPs found. Exiting.")
#        sys.exit(1)
#
#
#    security_group_ids = [
#        sg['GroupId']
#        for reservation in response['Reservations']
#        for instance in reservation['Instances']
#        for sg in instance['SecurityGroups']
#        if instance['InstanceId'] != exclude_instance_id
#    ]
#
#
#
###  Now that public_ips are all present, engage the multiprocessing on the instances with the 3 variant models
##   below for install_tomcat_on_instances main function. This function will use the ThreadPoolExecutor to 
##   install tomcat on the instances as detailed below and above. Main varaibles are num_processes and chunk_size
##   and max_workers (threads per process)
#
#
#
#
#    # Use multi-processing to distribute SSH connections across multiple cores
#
#    # with num_proceses = 6
#    #num_processes = os.cpu_count()
#    
#    # with num_procsses = 8
#    num_processes = 8
#
#    # the chunk_size is determined by number of instances divided by num_processes. num_processes is 6 and 
#    # number of instances is 50 so 50/6 = 8. The division is // for an integer with floor division
#    # this chunk size is then used to calculate the block of ips to pass to install_tomcat_on_instances (see below)
#    # for each process iteration i= 0 to num_processes-1 or 0 to 5 for processes 1 through 6
#    # Each process is assigned a block of 8 with the last 2 leftovers assigned to the last chunk which is assigned 
#    # to the last process #6. So the last process will get 10 ips to process. 
#    # As noted above the processes utlize install_tomcat_on_instances which runs ThreadPoolExecutor of 6 threads to
#    # process the assigned ip block.  So 6 ips handled immediately and the other 2 when any other thread frees up
#    # This minimizes contention and context switching.
#    
#
#### CHOOSE ONE MODEL BELOW:
#
#
#### MODEL 1:
### chunk_size determined by num_processes and number of IPs (deterministic)
### the remainder ips are processed by the last process and all the num_processes are used
##
##    chunk_size = len(instance_ips) // num_processes
##    processes = []
##
##    ## Debugging instance_ips
##    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
##    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')
##
##
##
##    for i in range(num_processes):
##        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
##        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
##        if i == num_processes - 1:  # Add remaining instances to the last chunk
##            chunk += instance_ips[(i + 1) * chunk_size:]
##        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
##        processes.append(process)
##        process.start()
##
##    for process in processes:
##        process.join()
##
##
#
#
#
#
#
#### MODEL 2 REMAINDER METHOD: (Don't use this. Use the revised version below)
#### Decouple chunk_size from num_processes and make sure remaining ips still get processed
#### the number of actual processes created is dynamic. For example with 50 IPs and chunk_size of 12, there will
#### be 4 processes created even though num_processes is 8.
#### NOTE only the required number of num_processes will be created (for production and optimized)
##
##    chunk_size = 12
##    processes = []
##
##
##    # adding debugs for instande_ips scope issue???
##    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
##    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')
##
##
##
##    # Calculate how many full chunks we actually need
##    num_chunks = len(instance_ips) // chunk_size
##    remainder = len(instance_ips) % chunk_size
##
##    for i in range(num_chunks):
##        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
##        
##        # If this is the last used chunk, add the remaining IPs
##        if i == num_chunks - 1 and remainder > 0:
##            chunk += instance_ips[(i + 1) * chunk_size:]
##
##        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
##        processes.append(process)
##        process.start()
##
##    for process in processes:
##        process.join()
##
##
#
#
### REVISED MODEL2: Using ceiling division and create an additional process to deal with leftover rather than adding
### it to the last process suing remainder method as above
###  This code is cleaner and also we don't need to deal with remainders
#
#    chunk_size = 20
#    processes = []
#
#    # Debugging instance_ips
#    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
#    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')
#
#    # Calculate how many chunks we need (ceiling division)
#    num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size
#
#    for i in range(num_chunks):
#        start = i * chunk_size
#        end = min(start + chunk_size, len(instance_ips))  # safely cap the end index
#        chunk = instance_ips[start:end]
#
#        # Diagnostic logging
#        print(f"[DEBUG] Process {i}: chunk size = {len(chunk)}")
#        print(f"[DEBUG] Process {i}: IPs = {[ip['PublicIpAddress'] for ip in chunk]}")
#
#        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
#        processes.append(process)
#        process.start()
#
#    for process in processes:
#        process.join()
#
#
#
#
#
#
#### MODEL 3: REMAINDER model. Do not use this.  Decouple chunk_size from num_processes and make sure remaining ips get processed but spawn
#### all num_processes for testing purposes
##
##
##    chunk_size = 12
##    processes = []
##
##    # Calculate how many full chunks we need
##    num_chunks = len(instance_ips) // chunk_size
##    remainder = len(instance_ips) % chunk_size
##
##
##    for i in range(num_processes):
##        if i < num_chunks:
##            chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
##            if i == num_chunks - 1 and remainder > 0:
##                chunk += instance_ips[(i + 1) * chunk_size:]
##            process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
##        else:
##            # Dummy process that just logs it's unused
##            process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
##        
##        processes.append(process)
##        process.start()
##
##    for process in processes:
##        process.join()#
##
#
#
#
#### REVISED MODEL3: Using ceiling devision. This model 3 will create num_processes and whatever is unused will just run
#### unused. This is just for testing purposes.
##
##    chunk_size = 12
##    processes = []
##
##    # Calculate how many chunks we need (ceiling division)
##    num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size
##
##    for i in range(num_processes):
##        if i < num_chunks:
##            start = i * chunk_size
##            end = min(start + chunk_size, len(instance_ips))
##            chunk = instance_ips[start:end]
## 
##            # Diagnostic logging
##            print(f"[DEBUG] Process {i}: chunk size = {len(chunk)}")
##            print(f"[DEBUG] Process {i}: IPs = {[ip['PublicIpAddress'] for ip in chunk]}")
##
##
##
##            process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
##        else:
##            # Dummy process that just logs it's unused
##            process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
##
##        processes.append(process)
##        process.start()
##
##    for process in processes:
##        process.join()
##
##
##
## We need to run main first when this is invoked from the master script. Then main will call the install_tomcat_on_instances to invoke the ThreadPoolExecutor for each process started in main.

#if __name__ == "__main__":
#    main()
