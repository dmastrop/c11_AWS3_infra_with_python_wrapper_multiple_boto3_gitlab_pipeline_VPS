###### TOP STUFF: Helper functions from module2 and imports, whitelist stuff, etc. #############



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
import ipaddress # used with the is_valid_ip helper function below. This function is used with the refactored ghost detection logic
# in resurrection_monitor_patch8 and is also used in the tomcat_worker "unknown" ip address rehydration code  that occurs with thread
# futures crashes.
import glob # need this for the aggregate stats function aggregate_process_stats in main()

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


##### Insertion of MCP CLient AI Request Sender block for the AI/MCP code integration
# ------------------------------------------------------------
# MCP CLIENT (AI Request Sender)
# ------------------------------------------------------------
# This object lives INSIDE module2f.
# It is responsible for sending JSON context to the AI Gateway
# and receiving the AI-generated recovery plan.
#
# module2f → MCPClient → AI Gateway → LLM → AI Gateway → MCPClient → module2f
#
# MCPClient NEVER interprets anything. It only:
#   - serializes context
#   - sends it to the AI Gateway
#   - receives the plan
#   - returns it to module2f
#
# module2f is the ONLY component that decides what to do with the plan.
# ------------------------------------------------------------

from my_mcp_client import MCPClient
# ^ This is the Python file that implements the MCPClient class.
#   This file is created in the repo (my_mcp_client.py).
#   It will define and contain a simple class that wraps requests.post().
#   The class has a method .send in it. The mcp.send() below is used to send/forward the context
#   to the AI Gateway Service (ai_gateway_service.py file in the repo)

# Create a global MCP client instance.
# This object will be reused for every AI request.
mcp = MCPClient(
    base_url="http://localhost:8000",   # AI Gateway Service URL
    schema_version="1.0"                # Optional versioning for future compatibility
)

def ask_ai_for_recovery(context: dict):
    """
    Send the failure context to the AI Gateway Service
    and return the AI-generated recovery plan.

    module2f calls THIS function inside the retry loop
    ONLY on the final failed attempt.
    """
    # mcp.send() performs:
    #   - JSON serialization
    #   - POST to http://localhost:8000/recover
    #   - returns parsed JSON from the AI Gateway
    return mcp.send(context)
## NOTE that the AI/MCP HOOK  is inside the def resurrection_install_tocmat function and is
## only activated on the last iteration of the command retry and only after all standard code heuristics have been 
## used to try to execute the command on the node. The AI/MCP HOOK is the last resort. It calls the 
## ask_ai_for_recovery function using the class defined above to send the context request to the AI Gateway Service
## which is in the python ai_gateway_service.py file in the repo.




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
# Note due to the way these regex lists are processed by pythnon always add the newer findings that are usually more broad
# to the top of the list. Python short-circuits the list upon getting a hit and this will optimize, especially under hyper-scaling

STRACE_WHITELIST_REGEX = [

    ## Test case 6 additions to remove process id exited with messages
    r"^\s*\d*\s*\+\+\+ exited with \d+ \+\+\+",
    r"^\s*\d*\s*execve\(.*\) = \d+",
    #r"^\s*\d*\s*write\(.*\) = \d+", # REMOVE THIS
    r"^\s*\d*\s*write\(1, .* = \d+",        # ✅ stdout-only



    # Test case 8 additions. We can remove all exited with <> patterns because we rewrite the exit_code variable with
    # a parse of this stderr from strace.  So there is no possiblity of an exited with 1, for example, with an exit_code
    # of 0.  
    # It is not stderr from the command itself — it’s an strace annotation. 
    # It’s metadata about the process exit, not a semantic error message. 
    r"\+\+\+ exited with \d+ \+\+\+",       # covers all strace exit codes
    r"execve\(.+\) = \d+",                  # general execve success/failure trace
    #r"write\(.+\) = \d+",                    # general write trace (stdout/stderr)


    #r"write\(2, .* = \d+\)",  # benign stderr writes REMOVE THIS
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

YUM_WHITELIST_REGEX = [
    r"Loaded plugins:.*",
    r"Resolving Dependencies",
    r"--> Running transaction check",
    r"--> Processing Dependency:.*",
    r"--> Finished Dependency Resolution",
    r"Dependencies Resolved",
    r"Transaction Summary",
    r"Install\s+\d+ Package\(s\)",
    r"Total download size: .*",
    r"Installed size: .*",
    r"Downloading packages:",
    r"Running transaction",
    r"Installing : .*",
    r"Verifying  : .*",
    r"Complete!",
    r"Package .* already installed and latest version",
    r"No package .* available",
    r"Nothing to do",
    r"Exiting on user command",
    r"Cleaning up",
    r"Not all dependencies resolved",
    r"Warning:.*",
    r"Public key for .* is not installed",
    r"Importing GPG key .*",
    r"Retrieving key from .*",
    r"Key imported successfully",
    r"yum update -y",
    r"yum install -y .*",
]


DNF_WHITELIST_REGEX = [
    r"Dependencies resolved",
    r"Transaction Summary",
    r"Install\s+\d+ Package\(s\)",
    r"Total download size: .*",
    r"Installed size: .*",
    r"Downloading Packages:",
    r"Running transaction",
    r"Preparing  : .*",
    r"Installing : .*",
    r"Verifying  : .*",
    r"Running scriptlet: .*",
    r"Complete!",
    r"Nothing to do",
    r"Package .* is already installed",
    r"No match for argument: .*",
    r"Error: Nothing to do",
    r"Importing GPG key .*",
    r"Retrieving key from .*",
    r"Key imported successfully",
    r"dnf install -y .*",
    r"dnf update -y",
    r"Warning:.*",
]



WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX + YUM_WHITELIST_REGEX + DNF_WHITELIST_REGEX

#WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX  # + YUM_WHITELIST_REGEX, etc.

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
    "no_tags",
    "ghost" # add this for the module2d resurrection_gateway code
}






##### Put at top of module for easy reference

##### Get rid of this. The adaptive watchdog timeout is per process and not global. 
#####  We will still use the WATCHDOG_TIMEOUT but it will be adaptive, calculated in get_watchdog_timeout and used by
##### read_output_with_watchdog which is called by install_tomcat


#### For Phase3 resurrection of threads just use a static 90 seconds. We don't need to get the adaptive watchdog timeout from
#### module2 because there is no API contention (the SG rules are already applied to the node that needs to be resurrected) and the
#### multi-processing and multi-threading is not done here. There is much less contention.

WATCHDOG_TIMEOUT          = 90   
# seconds before we declare a read stalled. This is the default. The WATCHDOG_TIMTOUE is now
# adaptive. See the function get_watchdog_timeout. 




##### These are used by the read_output_with_watchdog the raw output for STDOUT and STDERR of each thread.
RETRY_LIMIT               = 3    # number of re-executes per SSH command (for example install tomcat9)
SLEEP_BETWEEN_ATTEMPTS    = 5    # seconds to wait between retries
STALL_RETRY_THRESHOLD     = 1    # number of watchdog reattempts for each command in the for attempt loop. Note that this has
# nothing to do with the command attempt number. That is the number attempts in attempting to execute the command on the node.


##### This helper function is for the refactored ghost detection logic in resurrection_monitor_patch8 and also for the 
##### rehydration ip logic in tomcat_worker for the unknown ip address if futures thread crashes.
##### make sure to import ipaddress
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


##### helper functions for strace command support ########

## helper function used for the strace command syntax by the install_tomcat for idx commands/for attempt retry loop
## The strace code needs a trace.log file to hold its output prior to injecting it into stderr, and we need to 
## have unique trace.log filenames, and this appends a suffix to the trace_suffix.log filename. This prevents cross
## log corruption between command execution, retries of command execution at the per thread level. So 
## commands and retries all use unique trace.log filenames per thread.
def generate_trace_suffix():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


## helper functions for the wrapper for the strace command syntax. The commands[] list will be transformed to 
## native_commands (stripped of the strace) so that the user does not have to manually apply the strace transform to the 
## commands list.  The suspicious_patterns will be modified accordingly as the testing is done in this area.
## The should_wrap is the pre-processor and the wrap_command helper function actually applies the strace transform to the
## "native_command"
## Note that the /tmp/trace.log is re-written in install_tomcat and a trace_suffix is added to the trace.log name to make each
## trace.log unique for each command iterantion and each command retry iteration and unique per thread. This prevents 
## cross-contamination since the threads are multi-threaded in parallel and run in parallel processes.

#def should_wrap(cmd):
#    suspicious_patterns = [
#        r"sudo bash -c .*> /root/.*",
#        r"bash -c 'nonexistent_command'",
#        r"sudo touch /root/.*"
#    ]
#    return any(re.search(pat, cmd) for pat in suspicious_patterns)


def should_wrap(cmd):

    suspicious_patterns = [
        # Original bash-based patterns
        r"sudo bash -c .*?> /root/.*",
        r"bash -c .*nonexistent_command.*",
        r"sudo touch /root/.*",
        r"bash -c .*echo.*hello world.*",
        r"bash -c .*sudo /tmp/fail.sh.*",
        r"bash -c .*os\.write\(2,.*",
        r"bash -c .*exit 1.*",

        # New additions — python one-liners and stderr emitters
        r"python -c .*exit\(1\).*",
        r"python -c .*os\.write\(2,.*",
        r"python3 -c .*exit\(1\).*",
        r"python3 -c .*os\.write\(2,.*",

        # sh-based invocations
        r"sh -c .*exit 1.*",
        r"sh -c .*echo.*",

        # Direct exit calls
        r"exit 1",
        r"exit 2",
        r"exit 127",

        # Background jobs and pipes
        r".*\|.*",
        r".*&.*",

        # Subshells and chained commands
        r".*;.*",
        r".*&&.*",
        r".*\(.*\).*",

        # Sudo-wrapped brittle commands (but not apt/yum/dnf)
        r"sudo .*python.*",
        r"sudo .*fail.*",
    ]
    
    
    if any(re.search(pat, cmd) for pat in suspicious_patterns):
        return True
    if cmd.strip().startswith("bash -c"):
        return True
    return False




#def wrap_command(cmd):
#    if should_wrap(cmd):
#
#        return f"strace -e write,execve -o /tmp/trace.log {cmd} 2>/dev/null && cat /tmp/trace.log >&2"
#    return cmd


def wrap_command(cmd):
    matched = should_wrap(cmd)
    if matched:
        # debug: this is True and won't print anything if False
        #print(f"[{ip}] should_wrap matched: {matched}")
        #print(f"should_wrap matched: {matched}")
        print(f"should_wrap matched: {matched} → Command: {cmd}")
        #return f"strace -e write,execve -o /tmp/trace.log {cmd} 2>/dev/null && cat /tmp/trace.log >&2"

        return f"strace -f -e write,execve -o /tmp/trace.log {cmd} 2>/dev/null && cat /tmp/trace.log >&2"
        # -f is needed to follow forked subprocesses. Some commands do this and to get the non-whitelist material from them
        # in the strace output one needs to use the -f flag.
    return cmd


# Phase3 write_command_plan used in tomcat_worker right after the native_commands list is defined. This will be used by module2e
# to resurrect the threads using the command set list.   The filename is command_plan.json
def write_command_plan(native_commands, log_dir="/aws_EC2/logs"):
    wrapped = [wrap_command(cmd) for cmd in native_commands]
    plan = {
        "timestamp": datetime.utcnow().isoformat(),
        "native_commands": native_commands,
        "wrapped_commands": wrapped,
        "count": len(native_commands)
    }
    os.makedirs(log_dir, exist_ok=True)
    out = os.path.join(log_dir, "command_plan.json")
    with open(out, "w") as f:
        json.dump(plan, f, indent=2)
    print(f"[TRACE] Wrote command plan to {out}")




## Global function get_watchdog_timeout() to calculate the actual adaptive WATCHDOG_TIMEOUT based upon the parameters below
## This is code block2 for adaptive WATCHDOG_TIMEOUT


#def get_watchdog_timeout(node_count, instance_type, peak_retry_attempts):
def get_watchdog_timeout(node_count, instance_type, max_retry_observed):
    base = 15

    # use a scale map instead of just scale.

    SCALE_MAP = {
        "t2.micro": 0.15,
        "t2.small": 0.12,
        "default": 0.1
    }
    scale = SCALE_MAP.get(instance_type, SCALE_MAP["default"])

    #scale = 0.15 if instance_type == "micro" else 0.1

    #contention_penalty = min(30, peak_retry_attempts * 2)  # up to +30s
    contention_penalty = min(30, max_retry_observed * 2)  # up to +30s


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


##### REVISION2 of retry_with_backoff. We will return the number of unsuccessful attempts for the API call to 
##### my_ec2.authorize_security_group_ingress for each security group block (3 of them) used in the process
##### Each call will update the max_retry_observed to the highest attempt number, and when complete the 
##### max_retry_observed will have the maxiumm number of API calls that needed to be retried for that process' application
##### of the 3 security group rules to all the nodes(threads) in that process. It is a per process max count.
##### Note that the calls to retry_with_backoff are made from tomcat_worker (the 3 SG blocks) and max_retry_observed is
##### updated in that function, not this function. 
##### max_retry_observed is essentially a record keeper of the latest and highest attempt number from all 3 SG API calls 
##### as the rules are applied to the nodes in the process and is local only to tomcat_worker and not in retry_with_backoff

def retry_with_backoff(func, max_retries=15, base_delay=1, max_delay=10, *args, **kwargs):
    """
    Wraps an AWS API call with exponential backoff on RequestLimitExceeded.
    Returns the number of attempts it took to succeed (0-based).
    If all retries fail, returns max_retries.
    """
    print(f"[RETRY] Wrapper invoked for {func.__name__} with max_retries={max_retries}")

    for attempt in range(max_retries):
        try:
            if attempt == 0 and "authorize_security_group_ingress" in func.__name__:
                print(f"[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for {func.__name__}")

                # This is a synthetic injection to test the code. This will induce an attempt count of 1 and a 
                # RequestLimitExceeded for each SG call to this function. This is for testing purposes only.
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "RequestLimitExceeded", "Message": "Synthetic throttle"}},
                    "FakeOperation"
                )

            if attempt > 0:
                print(f"[RETRY] Attempt {attempt + 1} for {func.__name__} (args={args}, kwargs={kwargs})")

            result = func(*args, **kwargs) # execute the API call. In this case for the SG code blocks, they are calling 
            # my_ec2.authorize_security_group_ingress

            return attempt  # success on this attempt. If the result= func call is  not successful it will hit the except below
            # and the attempt index will be incremented.


        #### If RequestLimitExceeded then this if block below will be hit and use exponential backoff and then increment
        #### the attempt and try again with the if attempt > 0 block above submitting a new API request to AWS (attempt 1, 
        #### for example)
        except botocore.exceptions.ClientError as e:
            if "RequestLimitExceeded" in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)

            #### If the attempt succeeds then the call above will return the attempt. If that attempt fails due to 
            #### rule already exists, then we still want to return the current attempt count, even if duplicate.
            #### The current attempt count is a reflection of the API contention and we do not want to lose that metric
            #### in the adaptive watchdog calculation.
            elif "InvalidPermission.Duplicate" in str(e):
                print(f"[RETRY] Duplicate rule detected on attempt {attempt + 1}")
                return attempt  # ← return the attempt count even on duplicate



            ####  This will not return the attempt count. If this is hit something crashed.
            ####  - The API call **did not succeed**
            ####  - The error is **not one that has been explicitly handled**
            ####  - don’t want to treat a crash as a valid retry metric
            else:
                raise

    # All attempts failed
    print(f"[RETRY] Max retries exceeded for {func.__name__}")
    return max_retries


#### Add the WATCHDOG_TIMEOUT (timeout) to the read_output_with_watchdog. It is no longer global so replace the name
#### WATCHDOG_TIKMEOUT wiht timeout. It has beeen completely refactored to be process level rather than global.
#def read_output_with_watchdog(stream, label, ip):
def read_output_with_watchdog(stream, label, ip, timeout):



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
        #if elapsed > WATCHDOG_TIMEOUT:
        if elapsed > timeout:
            stall_count += 1
            print(f"[{ip}] ⏱️  Watchdog timeout on {label} read. Stall count: {stall_count}")
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




########## resurrection_install_tomcat function transplanted and stripped down from module2.
########## This version is srictly used for module2e registry resurrection threads 
########## The module2e registry resurrection_module2e_registry.json file will be used as an input, processed by
########## a wrapper orchestrator to extract out the args necessary for resurrection_install_tomcat() function below


def resurrection_install_tomcat(
    ip,
    private_ip,
    instance_id,
    WATCHDOG_TIMEOUT,
    replayed_commands,
    key_path="EC2_generic_key.pem",
    username="ubuntu",
    port=22,
    max_ssh_attempts=5,
    res_uuid=None,
    extra_tags=None # see below. extra_tags are the orignal tags from module2e registry. These will be added to base_tags (see below)
):
    """
    Replay a previously captured command set to resurrect a failed thread.
    - Uses module2e replayed_commands (already wrapped where needed).
    - Preserves whitelist-driven decision logic and strace exit overrides.
    - Tags a compact, forensic registry_entry for every outcome.

    Returns: (ip, private_ip, registry_entry)
    """
    

    import uuid
    import paramiko
    from datetime import datetime
    import threading
    import multiprocessing
    import time

    # -------------------------------------------------------------------------
    # This variable persists across the entire function and is used to store
    # the heuristic registry entry ONLY when AI successfully repairs a heuristic
    # failure. It must be defined here (top-level of the function) so that it
    # survives breaks out of the retry loop and remains visible to the final
    # install_success block. This is part of the larger AI/MCP integration into
    # module2f. This variable will be used throughout all of the heuristic failure
    # AI/MCP refactoring.
    # -------------------------------------------------------------------------
    heuristic_registry_entry_for_ai_command_success = None




    # Thread UUID (stable across a single resurrection run)
    thread_uuid = res_uuid or uuid.uuid4().hex[:8]
    
    # extend the base_tags with the extra_tags which is imported as an argument from the registry that is defined in main()
    # When main() calls this function, those extra_tags (original tags) are imported through the extra_tags arg above so that
    # they can be added to the new tags, and the historical forensics is intact. This updated base_tags now includes the 
    # original tags from the module2e registry that has been imported by main(), the calling function.

    base_tags = ["resurrection_attempt", "module2f"]
    if extra_tags:
        base_tags.extend(extra_tags)

    # Annotate ghost context if instance_id is None (for analytics transparency)
    # For example, with a synthetic ghost ip injection.
    if instance_id is None:
        base_tags.append("no_instance_id_context")
 
    # SSH_REFACTOR: remove these 2 lines. The refactor will do a per attempt loop ssh client (and close)
    # SSH connect with bounded retries + a stub watchdog on final attempt only
    #ssh = paramiko.SSHClient()
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_connected = False
    status_tagged = False # added for SSH_REFACTOR
    registry_entry_created = False # added for SSH_REFACTOR
    ssh_success = False  # temp flag to suppress the stub at the end. A setting of true will bypass the stub at the end.

    for attempt in range(max_ssh_attempts):
        try:
            # Final-attempt watchdog to prevent silent stalls from becoming ghosts
            def _watchdog():
                try:
                    time.sleep(30)
                    if not ssh_connected and attempt == (max_ssh_attempts - 1):
                        pid = multiprocessing.current_process().pid if multiprocessing.current_process() else None
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
                                "tags": base_tags + ["watchdog_triggered", "ssh_connect_stall"]
                            }
                            # Return path for stub handled by caller; here we just print
                            print(f"[RESURRECTION][{ip}] SSH watchdog stub tagged on final attempt.")
                except Exception as e:
                    print(f"[RESURRECTION][{ip}] Watchdog exception: {e}")

            threading.Thread(target=_watchdog, daemon=True).start() # uses the above function
            
            # SSH_REFACTOR replace these 4 lines with the block below this.
            #ssh.connect(ip, port, username, key_filename=key_path, timeout=45)
            #ssh_connected = True
            #ssh_success = True
            #break

            # SSH_REFACTOR
            ssh = paramiko.SSHClient() # new SSH client per attempt loop
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh_port = port  # avoid variable shadowing. The port is set via function args above (22)

            ssh.connect(
                hostname=ip,
                port=ssh_port,
                username=username,
                key_filename=key_path,
                timeout=30,
                banner_timeout=30,
                auth_timeout=30,
            )

            ssh_connected = True
            ssh_success = True
            break



        # SSH_REFACTOR:replace these except blocks with the full paramiko exception taxonomy
        
        #except paramiko.ssh_exception.NoValidConnectionsError as e:
        #    print(f"[{ip}] SSH NoValidConnectionsError attempt {attempt+1}: {e}")
        #    if attempt == (max_ssh_attempts - 1):
        #        registry_entry = {
        #            "status": "install_failed",
        #            "attempt": attempt,
        #            "pid": multiprocessing.current_process().pid,
        #            "thread_id": threading.get_ident(),
        #            "thread_uuid": thread_uuid,
        #            "public_ip": ip,
        #            "private_ip": private_ip,
        #            "timestamp": str(datetime.utcnow()),
        #            "tags": base_tags + ["ssh_exception", "NoValidConnectionsError", str(e)]
        #        }
        #        return ip, private_ip, registry_entry
        #    time.sleep(SLEEP_BETWEEN_ATTEMPTS)

        #except EOFError as e:
        #    print(f"[{ip}] SSH EOFError attempt {attempt+1}: {e}")
        #    if attempt == (max_ssh_attempts - 1):
        #        registry_entry = {
        #            "status": "install_failed",
        #            "attempt": attempt,
        #            "pid": multiprocessing.current_process().pid,
        #            "thread_id": threading.get_ident(),
        #            "thread_uuid": thread_uuid,
        #            "public_ip": ip,
        #            "private_ip": private_ip,
        #            "timestamp": str(datetime.utcnow()),
        #            "tags": base_tags + ["eof_error", "ssh_failure"]
        #        }
        #        return ip, private_ip, registry_entry
        #    time.sleep(SLEEP_BETWEEN_ATTEMPTS)




        # SSH_REFACTOR: new full paramiko exception taxonomy: close ssh, tag with base_tags, return registry_entry on final attempt, retry otherwise

        except TimeoutError as e:
            try: ssh.close()
            except: pass

            if attempt == max_ssh_attempts - 1:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": attempt,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + ["ssh_timeout", "TimeoutError", str(e)],
                }
                return ip, private_ip, registry_entry

            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
            continue

        except paramiko.ssh_exception.NoValidConnectionsError as e:
            try: ssh.close()
            except: pass

            if attempt == max_ssh_attempts - 1:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": attempt,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + ["ssh_exception", "NoValidConnectionsError", str(e)],
                }
                return ip, private_ip, registry_entry

            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
            continue

        except paramiko.ssh_exception.AuthenticationException as e:
            try: ssh.close()
            except: pass

            if attempt == max_ssh_attempts - 1:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": attempt,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + ["ssh_exception", "AuthenticationException", str(e)],
                }
                return ip, private_ip, registry_entry

            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
            continue

        except paramiko.ssh_exception.SSHException as e:
            try: ssh.close()
            except: pass

            if attempt == max_ssh_attempts - 1:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": attempt,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + ["ssh_exception", "SSHException", str(e)],
                }
                return ip, private_ip, registry_entry

            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
            continue

        except Exception as e:
            try: ssh.close()
            except: pass

            if attempt == max_ssh_attempts - 1:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": attempt,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + ["ssh_exception", "UnexpectedException", str(e)],
                }
                return ip, private_ip, registry_entry

            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
            continue

    #### else used with the for attempt in range(5) loop and try block above
    else:
        registry_entry = {
            "status": "ssh_retry_failed",
            "attempt": -1,
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "timestamp": str(datetime.utcnow()),
            "tags": base_tags + ["ssh_retry_failed"],
        }
        return ip, private_ip, registry_entry



    # SSH_REFACTOR replace this with module2 style stub guard further below.
    #if not ssh_success:
    #    # Early exit stub (rare): connection loop finished but didn’t set ssh_success
    #    pid = multiprocessing.current_process().pid
    #    stub_entry = {
    #        "status": "stub",
    #        "attempt": -1,
    #        "pid": pid,
    #        "thread_id": threading.get_ident(),
    #        "thread_uuid": thread_uuid,
    #        "public_ip": ip,
    #        "private_ip": private_ip,
    #        "timestamp": str(datetime.utcnow()),
    #        "tags": base_tags + ["ssh_init_failed", "early_exit"]
    #    }
    #    return ip, private_ip, stub_entry

    # SSH_REFACTOR replace the above with this new stub guard from module2:

    if not status_tagged and not registry_entry_created and not ssh_success:
        pid = multiprocessing.current_process().pid
        stub_entry = {
            "status": "stub",
            "attempt": -1,
            "pid": pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "timestamp": str(datetime.utcnow()),
            "tags": base_tags + ["stub", "early_exit", "ssh_init_failed"],
        }
        return ip, private_ip, stub_entry


    #### END of the SSH for attempt in range(5) block #####



    ##### initialize the following for the AI/MCP hook that has been inserted inside the for attempt loop (that is inside the for idx
    ##### loop below). These will be used in the AI/MCP hook code, and will be used for tagging the install_success and install_failed
    ##### cases when AI/MCP has or has not been invoked on a command to rescue the resurrection of  the node.
    ##### There are referred to as persistent state variables.

    ai_invoked = False
    ai_context = None
    ai_plan = None
    ai_fallback = False
    ai_commands = []



    # ------------------------------------------------------------
    # AI/MCP tagging helper (no control-flow changes)
    # This will be used in the registry_entrys that are towards the end of the for attempt in range loop, at the end of the 
    # for idx loop and for the try block exception registry_entry outside of the for attempt and for idx loops
    # This function runs POST AI/MCP HOOK, after AI has had a chance to work on the command for the thread. It will create the 
    # ai_tags and ai_meta lists and variables so that they can easily be added to the tags field of the registry_entry and 
    # added as an ai metadata field in the registry_entry.
    # ------------------------------------------------------------
    def _build_ai_metadata_and_tags():
        """
        Build a compact AI metadata dict and tag list for registry_entry.
        - Does NOT change control flow.
        - Safe to call from any registry_entry block.
        """
        ai_meta = {
            "ai_invoked": ai_invoked,
            "ai_fallback": ai_fallback,
            "ai_plan_action": ai_plan.get("action") if isinstance(ai_plan, dict) else None,
            "ai_commands": ai_commands[:] if isinstance(ai_commands, list) else [],
        }

        ai_tags = []

        # High-level flags
        if ai_invoked:
            ai_tags.append("ai_invoked_true")
        else:
            ai_tags.append("ai_invoked_false")

        if ai_fallback:
            ai_tags.append("ai_fallback_true")

        if isinstance(ai_plan, dict) and ai_plan.get("action"):
            ai_tags.append(f"ai_plan_action:{ai_plan.get('action')}")

        # Per-command AI assistance markers
        # Expectation: ai_commands is a list of dicts or strings.
        # If dict: look for {"command": "...", "ai_assisted": bool}
        # If string: assume AI-assisted command string.
        for entry in ai_meta["ai_commands"]:
            if isinstance(entry, dict):
                cmd = entry.get("command")
                assisted = entry.get("ai_assisted", False)
                if cmd and assisted:
                    ai_tags.append(f"ai_assisted:*{cmd}*")
            elif isinstance(entry, str):
                # Conservative: treat plain strings as AI-assisted commands
                ai_tags.append(f"ai_assisted:*{entry}*")

        return ai_meta, ai_tags
    # ------------------------------------------------------------



    # ------------------------------------------------------------
    # AI/MCP HOOK HELPER (FAITHFUL TO ORIGINAL HOOK)
    # So the original AI/MCP HOOK has been made into a helper function because it needs to be called from 
    # several different locations now. It has to be called from the original location towards the end of the for attemp
    # loop (command), but it also needs to be called from all of the heuristic failure blocks inside of the same for attept
    # command loop. In fact, thet most common scenario is that a difficult to execute command the will require AI assistance
    # will fail in one of the heuristic blocks rather than the original generic location (fall through) towards the end of
    # the for attempt command loop. The helper will make the integration much easier and compact.
    # ------------------------------------------------------------
    def _invoke_ai_hook(original_command, stdout_output, stderr_output,
                        exit_status, attempt, instance_id, ip,
                        extra_tags, ssh):
        """
        Unified AI/MCP hook for both heuristic failures and vanilla final-attempt failures.

        Returns a dict describing the outcome:


        (Below are control-flow variables in contrast to the nonlocal persistent state variables that are mutated directly
        The control-flow variables are returned from this HOOK helper functon and help control the program flow given the status
        of the ai helper application to the command. The persistent state variables on the other hand, help integrate the 
        ai/mcp state into the registry_entry via tags and ai-metadata fields.
        
        The key difference between the two are that control-flow variables are required since the HOOK is now a helper function
        and not inline in the def resurrection_install_tomcat function.  The control-flow variables must be returned by this
        HOOK helper so that module2f can use this information to continue program flow correctly for the thread.
        The persistent state variables are mutated directly since they are nonlocal in this HOOK helper. They do not need to 
        be returned to the calling function like the control-flow variables.)

        These are the control-flow variables

            {
                "ai_ran": True/False,
                "ai_fixed": True/False,
                "ai_failed": True/False,
                "ai_fallback": True/False,
                "new_stdout": "...",
                "new_stderr": "...",
                "new_exit_status": int,
            }
        
            This  HOOK is no longer inline
            So the caller needs a way to know:

                Did AI fix the command?

                Should I break the attempt loop?

                Should I continue retrying?

                Should I fall back to native logic?

                What is the updated stdout/stderr/exit_status?

                Persistent vars cannot answer these questions.

            Why is stedout/stderr/exti_status required as a return control-flow variable??
            Because the HOOK is no longer inline, the caller would otherwise lose:

                the retry command’s stdout

                the retry command’s stderr

                the retry command’s exit status

                These are needed for:
                heuristics

                classification

                registry entries

                exception handlers

                post‑mortem debugging

                So the helper must return them.

            Example of how the control-flow variables will be used by the caller:
                if result["ai_fixed"]:
                    stdout_output = result["new_stdout"]
                    stderr_output = result["new_stderr"]
                    exit_status = result["new_exit_status"]
                    command_succeeded = True
                    break



        These are the persistent state ai/mcp variables:

            nonlocal ai_invoked, ai_context, ai_plan, ai_fallback, ai_commands    
            
            These will be used to mutate the registry_entry and update it to what ai/mcp has done in terms of command execution 
            on the thread/registry_entry

            _build_ai_metadata_and_tags() reads these persistent state variables later and incorprates them into the 
            registry_entry using the ai_tags and ai_meta variables and lists.
        
            Example of how the persistent state variables are used to integrate into the registry_entry of a given thread:
            
                ai_meta, ai_tags = _build_ai_metadata_and_tags()

                Inside that helper: 
                    ai_meta = {
                        "ai_invoked": ai_invoked,
                        "ai_fallback": ai_fallback,
                        "ai_plan_action": ai_plan.get("action"),
                        "ai_commands": ai_commands[:],
                    }
            These live outside the HOOK helper and survive across:

                attempts

                commands

                heuristic blocks

                the entire resurrection run


        Why persistent vars cannot replace control‑flow vars
            Persistent vars indicate:

            “AI was invoked at some point”

            “Here is the plan AI chose”

            “Here are the commands AI ran”

            “AI fallback happened”

            But they do not indicate:

            “Did AI fix this command?”

            “Should I break the loop?”

            “Should I continue retrying?”

            “What is the updated exit status?”

            “What is the updated stderr?”

            Those are control‑flow decisions, not metadata.


        Why control‑flow vars cannot replace persistent vars
            Control‑flow vars are ephemeral:

            They only apply to the current HOOK invocation

            They do not survive across commands

            They do not survive across attempts

            They do not survive across heuristic blocks

            They are not used for tagging

            Persistent vars are the opposite:

            They survive across the entire resurrection run

            They are used for tagging

            They are used for metadata

            They are used for forensic lineage


        Complete code flow example:
            
            Step 1- HOOK helper (this function) runs:
            
            The HOOK helper mutates these persistent state variables directly as nonlocals:
                ai_invoked = True
                ai_plan = plan
                ai_fallback = False
                ai_commands.append(...)

            The helper returns these control-flow variables:
                {
                    "ai_ran": True,
                    "ai_fixed": True,
                    "new_stdout": "...",
                    "new_stderr": "",
                    "new_exit_status": 0
                }


            Step 2-  The caller uses these conrol-flow variables like this: (the persistent variables cannot control code flow like this)
            
            if result["ai_fixed"]:
                stdout_output = result["new_stdout"]
                stderr_output = result["new_stderr"]
                exit_status = result["new_exit_status"]
                command_succeeded = True
                break


            Step 3- Later the install_success block is run assuming the rest of the commands succeed in the command list
            
            The following code is used to append ai/mcp tags to the registry_entry for the thread, as well as ai metadata to the 
            registry_entry for the thread.

            ai_meta, ai_tags = _build_ai_metadata_and_tags()
            
            The helper _build_ai_metadata_and_tags can now read the mutated persistent state vars (from Step1 above) and 
            create the ai_meta list: 
            
            ai_meta = {
                "ai_invoked": ai_invoked,
                "ai_fallback": ai_fallback,
                "ai_plan_action": ai_plan.get("action"),
                "ai_commands": ai_commands[:],
            }

            The merged_tags can then be incorporated into the install_success registry_entry with the following, noting that NO
            historical forensic lineage/information has been lost from the original registry_entry tags:
                
                merged_tags = base_tags + [‘installation_completed’] + registry_entry[‘tags’] + ai_tags
            
            Likewise, the ai_meta can be added as a field to the install_success registry_entry    
         


        This helper:
            - Builds context
            - Calls ask_ai_for_recovery()
            - Updates ai_invoked, ai_plan, ai_fallback, ai_commands (persistent state variables) directly
            - Applies cleanup_and_retry or retry_with_modified_command
            - Re-runs the command through the SAME SSH connection
            - Returns updated outputs for classification and returns control-flow variables to the caller.
        """

        nonlocal ai_invoked, ai_context, ai_plan, ai_fallback, ai_commands  # These are the persistent state variables

        # --------------------------------------------------------
        # 1. Build the AI context payload (IDENTICAL TO ORIGINAL)
        # --------------------------------------------------------
        context = {
            "command": original_command,
            "stdout": stdout_output,
            "stderr": stderr_output,
            "exit_status": exit_status,
            "attempt": attempt + 1,
            "instance_id": instance_id,
            "ip": ip,
            "tags": extra_tags,
            "os_info": globals().get("os_info", None),
            "history": globals().get("command_history", None),
        }

        print(f"AI_MCP_HOOK[{ip}] 🔍 Invoking AI/MCP recovery engine...")
        plan = ask_ai_for_recovery(context)

        # --------------------------------------------------------
        # 2. Record AI invocation for tagging later
        # --------------------------------------------------------
        ai_invoked = True
        ai_context = context
        ai_plan = plan

        # --------------------------------------------------------
        # 3. Detect fallback conditions (IDENTICAL TO ORIGINAL)
        # --------------------------------------------------------
        if plan is None or plan.get("action") == "fallback" or "error" in plan:
            print(f"AI_MCP_HOOK[{ip}] ⚠️ AI fallback triggered — continuing with native logic.")
            ai_fallback = True
            return {
                "ai_ran": True,
                "ai_fixed": False,
                "ai_failed": True,
                "ai_fallback": True,
                "new_stdout": stdout_output,
                "new_stderr": stderr_output,
                "new_exit_status": exit_status,
            }

        # --------------------------------------------------------
        # 4. AI returned a valid plan — apply it (IDENTICAL LOGIC)
        # --------------------------------------------------------
        action = plan.get("action")
        print(f"AI_MCP_HOOK[{ip}] �� AI plan received: action={action}")

        # --------------------------------------------------------
        # ACTION: cleanup_and_retry
        # --------------------------------------------------------
        if action == "cleanup_and_retry":
            cleanup_cmds = plan.get("cleanup", [])
            retry_cmd = plan.get("retry")

            # Track commands for tagging
            ai_commands.extend(cleanup_cmds)
            if retry_cmd:
                ai_commands.append(retry_cmd)

            # ----------------------------------------------------
            # 5A. Run cleanup commands (IDENTICAL)
            # ----------------------------------------------------
            for ccmd in cleanup_cmds:
                print(f"AI_MCP_HOOK[{ip}] 🧹 AI cleanup: {ccmd}")
                cin, cout, cerr = ssh.exec_command(ccmd, timeout=60)
                cout.channel.settimeout(WATCHDOG_TIMEOUT)
                cerr.channel.settimeout(WATCHDOG_TIMEOUT)
                _co, _cs = read_output_with_watchdog(cout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                _eo, _es = read_output_with_watchdog(cerr, "STDERR", ip, WATCHDOG_TIMEOUT)

            # ----------------------------------------------------
            # 5B. Run retry command (IDENTICAL)
            # ----------------------------------------------------
            if retry_cmd:
                print(f"AI_MCP_HOOK[{ip}] 🔁 AI retry: {retry_cmd}")
                rin, rout, rerr = ssh.exec_command(retry_cmd, timeout=60)
                rout.channel.settimeout(WATCHDOG_TIMEOUT)
                rerr.channel.settimeout(WATCHDOG_TIMEOUT)

                r_stdout, _ = read_output_with_watchdog(rout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                r_stderr, _ = read_output_with_watchdog(rerr, "STDERR", ip, WATCHDOG_TIMEOUT)
                r_exit = rout.channel.recv_exit_status()

                print(f"AI_MCP_HOOK[{ip}] AI retry exit={r_exit}")

                # ------------------------------------------------
                # 5C. Re-evaluate success using SAME logic
                # ------------------------------------------------
                if r_exit == 0 and not r_stderr.strip():
                    print(f"AI_MCP_HOOK[{ip}] 🎉 AI successfully repaired the command!")
                    return {
                        "ai_ran": True,
                        "ai_fixed": True,
                        "ai_failed": False,
                        "ai_fallback": False,
                        "new_stdout": r_stdout,
                        "new_stderr": r_stderr,
                        "new_exit_status": r_exit,
                    }

                print(f"AI_MCP_HOOK[{ip}] ❌ AI retry failed — falling back to native logic.")
                return {
                    "ai_ran": True,
                    "ai_fixed": False,
                    "ai_failed": True,
                    "ai_fallback": False,
                    "new_stdout": r_stdout,
                    "new_stderr": r_stderr,
                    "new_exit_status": r_exit,
                }

        # --------------------------------------------------------
        # ACTION: retry_with_modified_command (IDENTICAL)
        # --------------------------------------------------------
        if action == "retry_with_modified_command":
            new_cmd = plan.get("retry")
            if new_cmd:
                ai_commands.append(new_cmd)
                print(f"AI_MCP_HOOK[{ip}] 🔁 AI modified retry: {new_cmd}")

                rin, rout, rerr = ssh.exec_command(new_cmd, timeout=60)
                rout.channel.settimeout(WATCHDOG_TIMEOUT)
                rerr.channel.settimeout(WATCHDOG_TIMEOUT)

                r_stdout, _ = read_output_with_watchdog(rout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                r_stderr, _ = read_output_with_watchdog(rerr, "STDERR", ip, WATCHDOG_TIMEOUT)
                r_exit = rout.channel.recv_exit_status()

                if r_exit == 0 and not r_stderr.strip():
                    print(f"AI_MCP_HOOK[{ip}] 🎉 AI modified command succeeded!")
                    return {
                        "ai_ran": True,
                        "ai_fixed": True,
                        "ai_failed": False,
                        "ai_fallback": False,
                        "new_stdout": r_stdout,
                        "new_stderr": r_stderr,
                        "new_exit_status": r_exit,
                    }

                print(f"AI_MCP_HOOK[{ip}] ❌ AI modified retry failed — falling back to native logic.")
                return {
                    "ai_ran": True,
                    "ai_fixed": False,
                    "ai_failed": True,
                    "ai_fallback": False,
                    "new_stdout": r_stdout,
                    "new_stderr": r_stderr,
                    "new_exit_status": r_exit,
                }

        # --------------------------------------------------------
        # ACTION: abort (IDENTICAL)
        # --------------------------------------------------------
        if action == "abort":
            print(f"AI_MCP_HOOK[{ip}] 🛑 AI instructed abort — tagging failure.")
            ai_commands.append("abort")
            return {
                "ai_ran": True,
                "ai_fixed": False,
                "ai_failed": True,
                "ai_fallback": False,
                "new_stdout": stdout_output,
                "new_stderr": stderr_output,
                "new_exit_status": exit_status,
            }

        # --------------------------------------------------------
        # Unknown action (IDENTICAL)
        # --------------------------------------------------------
        print(f"AI_MCP_HOOK[{ip}] ⚠️ Unknown AI action '{action}' — ignoring plan.")
        ai_fallback = True
        return {
            "ai_ran": True,
            "ai_fixed": False,
            "ai_failed": True,
            "ai_fallback": True,
            "new_stdout": stdout_output,
            "new_stderr": stderr_output,
            "new_exit_status": exit_status,
        }









    # Replay commands: whitelist-driven logic; strace exit overrides; adaptive watchdogs per stream
    try:
        for idx, command in enumerate(replayed_commands):
            # Each command retry loop
            command_succeeded = False
            original_command = command
            non_shell_failure_tag = None

            for attempt in range(RETRY_LIMIT):
                try:
                    # Ensure command is reset before mutation (for per-retry strace trace_path remapping)
                    command = original_command

                    if "strace" in command:
                        trace_suffix = generate_trace_suffix()
                        trace_path = f"/tmp/trace_{trace_suffix}.log"
                        command = command.replace("/tmp/trace.log", trace_path)

                    print(f"[{ip}] [{datetime.now()}] Replay {idx+1}/{len(replayed_commands)}: {command} (Attempt {attempt+1})")

                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)

                    stdout_output, stdout_stalled = read_output_with_watchdog(stdout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    stderr_output, stderr_stalled = read_output_with_watchdog(stderr, "STDERR", ip, WATCHDOG_TIMEOUT)

                    print(f"[{ip}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] STDERR: '{stderr_output.strip()}'")



                    ## COMMENT OUT this block and replace with the same heuristic but with AI/MCP integration (see below)
                    ## Known heuristic: apt missing package strings (kept minimal here)
                    #if "E: Package 'tomcat9'" in stderr_output:
                    #    if attempt == RETRY_LIMIT - 1:
                    #        registry_entry = {
                    #            "status": "install_failed",
                    #            "attempt": -1,
                    #            "pid": multiprocessing.current_process().pid,
                    #            "thread_id": threading.get_ident(),
                    #            "thread_uuid": thread_uuid,
                    #            "public_ip": ip,
                    #            "private_ip": private_ip,
                    #            "timestamp": str(datetime.utcnow()),
                    #            "tags": base_tags + [
                    #                "fatal_package_missing",
                    #                command,
                    #                f"command_retry_{attempt + 1}",
                    #                *stderr_output.strip().splitlines()[:12]
                    #            ]
                    #        }
                    #        ssh.close()
                    #        return ip, private_ip, registry_entry
                    #    else:
                    #        print(f"[{ip}] Package missing — retrying...")
                    #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    #        continue





                    # -------------------------------------------------------------------------
                    # Heuristic Block #1 with AI/MCP integration: Missing apt package (e.g., tomcat9)
                    #
                    # IMPORTANT NOTE ABOUT CONTROL FLOW AND VARIABLE SCOPE:
                    # -----------------------------------------------------
                    # This block constructs a heuristic failure registry entry. If AI fails to
                    # repair the issue, we RETURN immediately — which exits the ENTIRE function.
                    #
                    # HOWEVER:
                    # If AI *fixes* the issue, we BREAK out of the retry loop instead of returning.
                    # A break continues execution of the outer loops and eventually reaches the
                    # install_success block.
                    #
                    # Because of this:
                    #   - We CANNOT return the heuristic registry entry when AI fixes the issue.
                    #   - We MUST preserve the heuristic registry entry so install_success can
                    #     merge its tags into the final success registry entry.
                    #
                    # Therefore:
                    #   - We define `heuristic_registry_entry_for_ai_command_success` at the TOP
                    #     of the function (outside all loops) so it survives the break.
                    #   - We assign to it here ONLY when AI successfully repairs the heuristic
                    #     failure.
                    # -------------------------------------------------------------------------

                    if "E: Package 'tomcat9'" in stderr_output:

                        if attempt == RETRY_LIMIT - 1:

                            # Build the heuristic failure registry entry
                            heuristic_registry_entry = {
                                "status": "install_failed",
                                "attempt": -1,
                                "pid": multiprocessing.current_process().pid,
                                "thread_id": threading.get_ident(),
                                "thread_uuid": thread_uuid,
                                "public_ip": ip,
                                "private_ip": private_ip,
                                "timestamp": str(datetime.utcnow()),
                                "tags": base_tags + [
                                    "fatal_package_missing",
                                    command,
                                    f"command_retry_{attempt + 1}",
                                    *stderr_output.strip().splitlines()[:12],
                                ],
                            }

                            # ------------------------------------------------------------
                            # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                            # ------------------------------------------------------------
                            extra_tags = heuristic_registry_entry["tags"]
                            result = _invoke_ai_hook(
                                original_command=original_command,
                                stdout_output=stdout_output,
                                stderr_output=stderr_output,
                                exit_status=exit_status,
                                attempt=attempt,
                                instance_id=instance_id,
                                ip=ip,
                                extra_tags=extra_tags,
                                ssh=ssh,
                            )

                            # ------------------------------------------------------------
                            # CASE A: AI FIXED THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            if result["ai_fixed"]:
                                # Update outputs with AI-repaired results
                                stdout_output = result["new_stdout"]
                                stderr_output = result["new_stderr"]
                                exit_status = result["new_exit_status"]

                                command_succeeded = True

                                # Preserve the heuristic registry entry for install_success.
                                # This variable is defined at the TOP of the function so it
                                # survives the break and is visible to install_success.
                                heuristic_registry_entry_for_ai_command_success = heuristic_registry_entry

                                # DO NOT RETURN — returning would exit the entire function.
                                # We break so the idx loop continues and install_success runs.
                                break

                            # ------------------------------------------------------------
                            # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            ai_meta, ai_tags = _build_ai_metadata_and_tags()
                            heuristic_registry_entry["ai_metadata"] = ai_meta
                            heuristic_registry_entry["tags"].extend(ai_tags)

                            ssh.close()
                            return ip, private_ip, heuristic_registry_entry

                        else:
                            print(f"[{ip}] Package missing — retrying...")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue





                    # Whitelist filtering
                    stderr_lines = stderr_output.strip().splitlines()
                    non_whitelisted_lines = [line for line in stderr_lines if not is_whitelisted_line(line)]

                    stdout_lines = stdout_output.strip().splitlines()
                    stdout_blacklisted_lines = [line for line in stdout_lines if not is_whitelisted_line(line)]

                    # Exit status, possibly overridden by strace parsing
                    exit_status = stdout.channel.recv_exit_status()

                    tags = []
                    


                    ###### strace logic begins ######

                    if "strace" in command and not stderr_output.strip():
                        # Extract trace_path from command
                        try:
                            trace_path_extracted = command.split("-o")[1].split()[0].strip()
                        except Exception:
                            trace_path_extracted = trace_path  # fallback to current mutation

                        trace_in, trace_out, trace_err = ssh.exec_command(f"cat {trace_path_extracted}")
                        trace_output = trace_out.read().decode()
                        stderr_output = trace_output

                        # Find final exit status for shell PID, fallback to last seen if shell PID inference fails
                        exit_lines = re.findall(r"(\d+)\s+\+\+\+ exited with (\d+) \+\+\+", trace_output)
                        shell_pid = None
                        shell_pid_match = re.search(r"(\d+)\s+execve\(\"/usr/bin/bash\",", trace_output)
                        if shell_pid_match:
                            shell_pid = shell_pid_match.group(1)
                            for pid_line, status_line in exit_lines:
                                if pid_line == shell_pid:
                                    exit_status = int(status_line)
                                    break
                            else:
                                if exit_lines:
                                    exit_status = int(exit_lines[-1][1])
                                else:
                                    tags.append("fallback_exit_status")
                        else:
                            if exit_lines:
                                exit_status = int(exit_lines[-1][1])
                            else:
                                tags.append("fallback_exit_status")

                        # Non-shell failure tag (informational)
                        non_shell_failures = [
                            (pid_line, status_line) for pid_line, status_line in exit_lines
                            if shell_pid and pid_line != shell_pid and int(status_line) != 0
                        ]
                        if non_shell_failures:
                            non_shell_failure_tag = f"non_shell_exit_failure: {non_shell_failures}"

                        # Recompute whitelist sets after injection
                        stderr_lines = stderr_output.strip().splitlines()
                        non_whitelisted_lines = [line for line in stderr_lines if not is_whitelisted_line(line)]
                        stdout_lines = stdout_output.strip().splitlines()
                        stdout_blacklisted_lines = [line for line in stdout_lines if not is_whitelisted_line(line)]

                        


                        ###### strace heuristic failure blocks #########
                        

                        ### COMMENT OUT this block and replace with AI/MCP refactored code (see below)
                        ## Non-zero exit => fail (final), else retry
                        #if exit_status != 0:
                        #    if attempt == RETRY_LIMIT - 1:
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
                        #                "tags": base_tags + [
                        #                    "fatal_exit_nonzero",
                        #                    command,
                        #                    f"command_retry_{attempt + 1}",
                        #                    f"exit_status_{exit_status}",
                        #                    "stderr_present",
                        #                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],
                        #                    *stderr_output.strip().splitlines()[:25]
                        #                ]
                        #            }
                        #        else:
                        #            registry_entry = {
                        #                "status": "stub",
                        #                "attempt": -1,
                        #                "pid": multiprocessing.current_process().pid,
                        #                "thread_id": threading.get_ident(),
                        #                "thread_uuid": thread_uuid,
                        #                "public_ip": ip,
                        #                "private_ip": private_ip,
                        #                "timestamp": str(datetime.utcnow()),
                        #                "tags": base_tags + [
                        #                    #*(tags or []), ## This is not required as base_tags has already been extended. See extra_tags
                        #                    "silent_failure",
                        #                    command,
                        #                    f"command_retry_{attempt + 1}",
                        #                    f"exit_status_{exit_status}",
                        #                    "exit_status_nonzero_stderr_blank"
                        #                ]
                        #            }
                        #        ssh.close()
                        #        return ip, private_ip, registry_entry
                        #    else:
                        #        print(f"[{ip}] Non-zero exit — retrying...")
                        #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                        #        continue

                        ###### Heuristic Block #2 with AI/MCP integration: strace fatal_exit_nonzero ######
                        # NOTE:
                        #   See Heuristic Block #1 for the full explanation of:
                        #     - why we cannot return on AI-fixed cases,
                        #     - why we must preserve the heuristic registry entry,
                        #     - why the persistent variable is defined at the top of the function.
                        #   This block follows the same Step 5b pattern with shorter comments.

                        # Non-zero exit => fail (final), else retry
                        if exit_status != 0:
                            if attempt == RETRY_LIMIT - 1:
                                if stderr_output.strip():
                                    registry_entry = {
                                        "status": "install_failed",
                                        "attempt": -1,
                                        "pid": multiprocessing.current_process().pid,
                                        "thread_id": threading.get_ident(),
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": str(datetime.utcnow()),
                                        "tags": base_tags + [
                                            "fatal_exit_nonzero",
                                            command,
                                            f"command_retry_{attempt + 1}",
                                            f"exit_status_{exit_status}",
                                            "stderr_present",
                                            *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],
                                            *stderr_output.strip().splitlines()[:25]
                                        ]
                                    }
                                else:
                                    registry_entry = {
                                        "status": "stub",
                                        "attempt": -1,
                                        "pid": multiprocessing.current_process().pid,
                                        "thread_id": threading.get_ident(),
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": str(datetime.utcnow()),
                                        "tags": base_tags + [
                                            #*(tags or []), ## This is not required as base_tags has already been extended. See extra_tags
                                            "silent_failure",
                                            command,
                                            f"command_retry_{attempt + 1}",
                                            f"exit_status_{exit_status}",
                                            "exit_status_nonzero_stderr_blank"
                                        ]
                                    }

                                # ------------------------------------------------------------
                                # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                                # ------------------------------------------------------------
                                extra_tags = registry_entry["tags"]
                                result = _invoke_ai_hook(
                                    original_command=original_command,
                                    stdout_output=stdout_output,
                                    stderr_output=stderr_output,
                                    exit_status=exit_status,
                                    attempt=attempt,
                                    instance_id=instance_id,
                                    ip=ip,
                                    extra_tags=extra_tags,
                                    ssh=ssh,
                                )

                                # ------------------------------------------------------------
                                # CASE A: AI FIXED THE HEURISTIC FAILURE
                                # ------------------------------------------------------------
                                if result["ai_fixed"]:
                                    # Update outputs with AI-repaired results
                                    stdout_output = result["new_stdout"]
                                    stderr_output = result["new_stderr"]
                                    exit_status = result["new_exit_status"]

                                    command_succeeded = True

                                    # Preserve the heuristic registry entry for install_success.
                                    # This variable is defined at the TOP of the function so it
                                    # survives the break and is visible to install_success.
                                    heuristic_registry_entry_for_ai_command_success = registry_entry

                                    # DO NOT RETURN — returning would exit the entire function.
                                    # We break so the idx loop continues and install_success runs.
                                    break

                                # ------------------------------------------------------------
                                # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                                # ------------------------------------------------------------
                                ai_meta, ai_tags = _build_ai_metadata_and_tags()
                                registry_entry["ai_metadata"] = ai_meta
                                registry_entry["tags"].extend(ai_tags)

                                ssh.close()
                                return ip, private_ip, registry_entry
                            else:
                                print(f"[{ip}] Non-zero exit — retrying...")
                                time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                                continue




                        ## COMMENT OUT the heuristic3 code below for the AI/MCP refactored code below 
                        ## Zero exit, but non-whitelisted stderr => fail on final attempt, else retry
                        #if non_whitelisted_lines:
                        #    if attempt == RETRY_LIMIT - 1:
                        #        registry_entry = {
                        #            "status": "install_failed",
                        #            "attempt": -1,
                        #            "pid": multiprocessing.current_process().pid,
                        #            "thread_id": threading.get_ident(),
                        #            "thread_uuid": thread_uuid,
                        #            "public_ip": ip,
                        #            "private_ip": private_ip,
                        #            "timestamp": str(datetime.utcnow()),
                        #            "tags": base_tags + [
                        #            
                        #                "stderr_detected",  ##### MODULE2 spliced in code and refactored. Starts here. This needs to be refactored for module2f. Do as minimal edits as possible and leave in the comments so I can identify this. 
                        #                command,
                        #                f"command_retry_{attempt + 1}",
                        #                "exit_status_zero",   # We know exit_status is zero here.
                        #                "non_whitelisted_stderr",
                        #                *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # First few lines for traceability.
                        #                *stderr_output.strip().splitlines()[:25]  # Snapshot for traceability.
                        #            ]
                        #        }
                        #        #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up trace log
                        #        ssh.close()
                        #        return ip, private_ip, registry_entry
                        #    else:
                        #        print(f"[{ip}] ⚠️ Unexpected strace stderr — retrying attempt {attempt + 1}")
                        #        #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before retry
                        #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                        #        continue



                        ###### Heuristic Block #3 with AI/MCP integration: strace zero-exit + non-whitelisted stderr ######
                        # NOTE:
                        #   See Heuristic Block #1 for the full explanation of:
                        #     - break vs return semantics,
                        #     - why we must preserve heuristic registry entries,
                        #     - why the persistent variable is defined at the top of the function.
                        #   This block follows the same Step 5b pattern with shorter comments.

                        # Zero exit, but non-whitelisted stderr => fail on final attempt, else retry
                        if non_whitelisted_lines:
                            if attempt == RETRY_LIMIT - 1:
                                registry_entry = {
                                    "status": "install_failed",
                                    "attempt": -1,
                                    "pid": multiprocessing.current_process().pid,
                                    "thread_id": threading.get_ident(),
                                    "thread_uuid": thread_uuid,
                                    "public_ip": ip,
                                    "private_ip": private_ip,
                                    "timestamp": str(datetime.utcnow()),
                                    "tags": base_tags + [
                                        "stderr_detected",  ##### MODULE2 spliced in code and refactored. Starts here. This needs to be refactored for module2f. Do as minimal edits as possible and leave in the comments so I can identify this. 
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        "exit_status_zero",   # We know exit_status is zero here.
                                        "non_whitelisted_stderr",
                                        *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # First few lines for traceability.
                                        *stderr_output.strip().splitlines()[:25]  # Snapshot for traceability.
                                    ]
                                }
                                #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up trace log
                                
                                # ------------------------------------------------------------
                                # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                                # ------------------------------------------------------------
                                extra_tags = registry_entry["tags"]
                                result = _invoke_ai_hook(
                                    original_command=original_command,
                                    stdout_output=stdout_output,
                                    stderr_output=stderr_output,
                                    exit_status=exit_status,
                                    attempt=attempt,
                                    instance_id=instance_id,
                                    ip=ip,
                                    extra_tags=extra_tags,
                                    ssh=ssh,
                                )

                                # ------------------------------------------------------------
                                # CASE A: AI FIXED THE HEURISTIC FAILURE
                                # ------------------------------------------------------------
                                if result["ai_fixed"]:
                                    # Update outputs with AI-repaired results
                                    stdout_output = result["new_stdout"]
                                    stderr_output = result["new_stderr"]
                                    exit_status = result["new_exit_status"]

                                    command_succeeded = True

                                    # Preserve the heuristic registry entry for install_success.
                                    # This variable is defined at the TOP of the function so it
                                    # survives the break and is visible to install_success.
                                    heuristic_registry_entry_for_ai_command_success = registry_entry

                                    # DO NOT RETURN — returning would exit the entire function.
                                    # We break so the idx loop continues and install_success runs.
                                    break

                                # ------------------------------------------------------------
                                # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                                # ------------------------------------------------------------
                                ai_meta, ai_tags = _build_ai_metadata_and_tags()
                                registry_entry["ai_metadata"] = ai_meta
                                registry_entry["tags"].extend(ai_tags)

                                ssh.close()
                                return ip, private_ip, registry_entry
                            else:
                                print(f"[{ip}] ⚠️ Unexpected strace stderr — retrying attempt {attempt + 1}")
                                #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before retry
                                time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                                continue





                    ###### End of strace if block and strace logic #########




                    ###############################################
                    ############ non-strace heursitic logic: #################    


                    #print(f"[{ip}] ✅ Final exit_status used for registry logic: {exit_status}")


                    ## 🔍 Case 1: Non-zero exit status — failure or stub
                    #if exit_status != 0:
                    #    if attempt == RETRY_LIMIT - 1:
                    #        pid = multiprocessing.current_process().pid
                    #        thread_id = threading.get_ident()
                    #        timestamp = str(datetime.utcnow())

                    #        if stderr_output.strip():
                    #            registry_entry = {
                    #                "status": "install_failed",
                    #                "attempt": -1,
                    #                "pid": pid,
                    #                "thread_id": thread_id,
                    #                "thread_uuid": thread_uuid,
                    #                "public_ip": ip,
                    #                "private_ip": private_ip,
                    #                "timestamp": timestamp,
                    #                "tags": base_tags + [
                    #                #"tags": [
                    #                    "fatal_exit_nonzero",
                    #                    command,
                    #                    f"command_retry_{attempt + 1}",
                    #                    f"exit_status_{exit_status}",
                    #                    "stderr_present",
                    #                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # include first few lines for forensic trace
                    #                    *stderr_output.strip().splitlines()[:25]  # snapshot for traceability
                    #                ]
                    #            }
                    #        else:
                    #            registry_entry = {
                    #                "status": "stub",
                    #                "attempt": -1,
                    #                "pid": pid,
                    #                "thread_id": thread_id,
                    #                "thread_uuid": thread_uuid,
                    #                "public_ip": ip,
                    #                "private_ip": private_ip,
                    #                "timestamp": timestamp,
                    #                "tags": base_tags + [
                    #                #"tags": [
                    #                    "silent_failure",
                    #                    command,
                    #                    f"command_retry_{attempt + 1}",
                    #                    f"exit_status_{exit_status}",
                    #                    "exit_status_nonzero_stderr_blank"
                    #                ]
                    #            }
                    #        ssh.close()
                    #        return ip, private_ip, registry_entry
                    #    else:
                    #        print(f"[{ip}] ⚠️ Non-zero exit — retrying attempt {attempt + 1}")
                    #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    #        continue
                    



                    ###### Heuristic Block #4 with AI/MCP integration: non-strace fatal_exit_nonzero ######
                    # NOTE:
                    #   This block mirrors Heuristic Block #2 (strace) and follows the same
                    #   Step 5b pattern for invoking the AI/MCP hook on the final attempt.
                    #   Keep the persistent variable `heuristic_registry_entry_for_ai_command_success`
                    #   defined at the TOP of the function so it survives the break path.
                    #
                    # Non-zero exit => fail (final), else retry
                    # 🔍 Case 1: Non-zero exit status — failure or stub
                    if exit_status != 0:
                        if attempt == RETRY_LIMIT - 1:
                            # Capture process/thread/timestamp for forensic registry entry.
                            # We assign to locals here for readability; the registry uses these values.
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
                                    "tags": base_tags + [
                                        "fatal_exit_nonzero",
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        f"exit_status_{exit_status}",
                                        "stderr_present",
                                        *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # include first few lines for forensic trace
                                        *stderr_output.strip().splitlines()[:25]  # snapshot for traceability
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
                                    "tags": base_tags + [
                                        "silent_failure",
                                        command,
                                        f"command_retry_{attempt + 1}",
                                        f"exit_status_{exit_status}",
                                        "exit_status_nonzero_stderr_blank"
                                    ]
                                }

                            # ------------------------------------------------------------
                            # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                            # ------------------------------------------------------------
                            # We call the AI hook here on the final attempt. If the AI repairs
                            # the outputs we must NOT return immediately — instead we set the
                            # persistent registry variable and break so install_success runs.
                            extra_tags = registry_entry["tags"]
                            result = _invoke_ai_hook(
                                original_command=original_command,
                                stdout_output=stdout_output,
                                stderr_output=stderr_output,
                                exit_status=exit_status,
                                attempt=attempt,
                                instance_id=instance_id,
                                ip=ip,
                                extra_tags=extra_tags,
                                ssh=ssh,
                            )

                            # ------------------------------------------------------------
                            # CASE A: AI FIXED THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            if result["ai_fixed"]:
                                # Update outputs with AI-repaired results
                                stdout_output = result["new_stdout"]
                                stderr_output = result["new_stderr"]
                                exit_status = result["new_exit_status"]

                                command_succeeded = True

                                # Preserve the heuristic registry entry for install_success.
                                # This variable is defined at the TOP of the function so it
                                # survives the break and is visible to install_success.
                                heuristic_registry_entry_for_ai_command_success = registry_entry

                                # DO NOT RETURN — returning would exit the entire function.
                                # We break so the idx loop continues and install_success runs.
                                break

                            # ------------------------------------------------------------
                            # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            # Attach AI metadata and tags for forensic/telemetry purposes,
                            # then close SSH and return the registry entry as a failure.
                            ai_meta, ai_tags = _build_ai_metadata_and_tags()
                            registry_entry["ai_metadata"] = ai_meta
                            registry_entry["tags"].extend(ai_tags)

                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            # Non-final attempt: log and retry after a short sleep.
                            print(f"[{ip}] ⚠️ Non-zero exit — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue


                    ## 🔍 Case 2: Zero exit but non-whitelisted stderr — unexpected failure
                    #elif non_whitelisted_lines:
                    #    if attempt == RETRY_LIMIT - 1:
                    #        pid = multiprocessing.current_process().pid
                    #        thread_id = threading.get_ident()
                    #        timestamp = str(datetime.utcnow())

                    #        registry_entry = {
                    #            "status": "install_failed",
                    #            "attempt": -1,
                    #            "pid": pid,
                    #            "thread_id": thread_id,
                    #            "thread_uuid": thread_uuid,
                    #            "public_ip": ip,
                    #            "private_ip": private_ip,
                    #            "timestamp": timestamp,
                    #            "tags": base_tags + [
                    #            #"tags": [      ## END of Module2 splice

                    #                    "stderr_detected",
                    #                    command,
                    #                    f"command_retry_{attempt + 1}",
                    #                    "exit_status_zero",
                    #                    "non_whitelisted_stderr",
                    #                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],
                    #                    *stderr_output.strip().splitlines()[:25]
                    #                ]
                    #            }
                    #        ssh.close()
                    #        return ip, private_ip, registry_entry
                    #    else:
                    #        print(f"[{ip}] Unexpected stderr — retrying...")
                    #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    #        continue



                    ###### Heuristic Block #5 with AI/MCP integration: non-strace zero-exit + non-whitelisted stderr ######
                    # NOTE:
                    #   Mirrors Heuristic Block #3 (strace) and follows the same Step 5b pattern.
                    #   Keep the persistent variable `heuristic_registry_entry_for_ai_command_success`
                    #   defined at the TOP of the function so it survives the break path.
                    #
                    # Zero exit, but non-whitelisted stderr => fail on final attempt, else retry
                    elif non_whitelisted_lines:
                        if attempt == RETRY_LIMIT - 1:
                            # Capture process/thread/timestamp for forensic registry entry.
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
                                "tags": base_tags + [
                                    "stderr_detected",
                                    command,
                                    f"command_retry_{attempt + 1}",
                                    "exit_status_zero",
                                    "non_whitelisted_stderr",
                                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],
                                    *stderr_output.strip().splitlines()[:25]
                                ]
                            }
                            # ------------------------------------------------------------
                            # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                            # ------------------------------------------------------------
                            # We call the AI hook here on the final attempt. If the AI repairs
                            # the outputs we must NOT return immediately — instead we set the
                            # persistent registry variable and break so install_success runs.
                            extra_tags = registry_entry["tags"]
                            result = _invoke_ai_hook(
                                original_command=original_command,
                                stdout_output=stdout_output,
                                stderr_output=stderr_output,
                                exit_status=exit_status,
                                attempt=attempt,
                                instance_id=instance_id,
                                ip=ip,
                                extra_tags=extra_tags,
                                ssh=ssh,
                            )

                            # ------------------------------------------------------------
                            # CASE A: AI FIXED THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            if result["ai_fixed"]:
                                # Update outputs with AI-repaired results
                                stdout_output = result["new_stdout"]
                                stderr_output = result["new_stderr"]
                                exit_status = result["new_exit_status"]

                                command_succeeded = True

                                # Preserve the heuristic registry entry for install_success.
                                # This variable is defined at the TOP of the function so it
                                # survives the break and is visible to install_success.
                                heuristic_registry_entry_for_ai_command_success = registry_entry

                                # DO NOT RETURN — returning would exit the entire function.
                                # We break so the idx loop continues and install_success runs.
                                break

                            # ------------------------------------------------------------
                            # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            # Attach AI metadata and tags for forensic/telemetry purposes,
                            # then close SSH and return the registry entry as a failure.
                            ai_meta, ai_tags = _build_ai_metadata_and_tags()
                            registry_entry["ai_metadata"] = ai_meta
                            registry_entry["tags"].extend(ai_tags)

                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            # Non-final attempt: log and retry after a short sleep.
                            print(f"[{ip}] Unexpected stderr — retrying...")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

                    ##### end of non-strace logic ##########













                    ##### end of non-strace logic ##########





                    # Success
                    command_succeeded = True
                    time.sleep(5)  # keep this short in resurrection
                    break




                    #### Another splice from module2 starts here ####
                    
                    ### Modify the above to fail ONLY if it is the LAST attempt> we do not want to prematurely create stubs
                    ### and failed registry entries uniless all retries have been exhausted
                    ## ⚠️ Unexpected stderr — retry instead of exiting
                    #if stderr_output.strip():
                    #    if attempt == RETRY_LIMIT - 1:
                    #        print(f"[{ip}] ❌ Unexpected stderr on final attempt — tagging failure")
                    #        registry_entry = {
                    #            "status": "install_failed",
                    #            "attempt": -1,
                    #            "pid": multiprocessing.current_process().pid,
                    #            "thread_id": threading.get_ident(),
                    #            "thread_uuid": thread_uuid,
                    #            "public_ip": ip,
                    #            "private_ip": private_ip,
                    #            "timestamp": str(datetime.utcnow()),
                    #            "tags": base_tags + [
                    #            #"tags": [
                    #                "stderr_detected",
                    #                command,
                    #                f"command_retry_{attempt + 1}",  # e.g. command_retry_3
                    #                *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                    #            ]
                    #        }
                    #        ssh.close()
                    #        return ip, private_ip, registry_entry
                    #    else:
                    #        print(f"[{ip}] ⚠️ Unexpected stderr — retrying attempt {attempt + 1}")
                    #        time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    #        continue




                    ##### Heuristic Block #6 with AI/MCP integration  ######
                    ## Modify the above to fail ONLY if it is the LAST attempt — do not create stubs prematurely
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
                                "tags": base_tags + [
                                    "stderr_detected",
                                    command,
                                    f"command_retry_{attempt + 1}",  # e.g. command_retry_3
                                    *stderr_output.strip().splitlines()[:12]  # snapshot for traceability
                                ]
                            }

                            # ------------------------------------------------------------
                            # Step 5b: Invoke AI/MCP HOOK for this heuristic failure (_invoke_ai_hook())
                            # ------------------------------------------------------------
                            # We call the AI hook here on the final attempt. If the AI repairs
                            # the outputs we must NOT return immediately — instead we set the
                            # persistent registry variable and break so install_success runs.
                            extra_tags = registry_entry["tags"]
                            result = _invoke_ai_hook(
                                original_command=original_command,
                                stdout_output=stdout_output,
                                stderr_output=stderr_output,
                                exit_status=exit_status,
                                attempt=attempt,
                                instance_id=instance_id,
                                ip=ip,
                                extra_tags=extra_tags,
                                ssh=ssh,
                            )

                            # ------------------------------------------------------------
                            # CASE A: AI FIXED THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            if result["ai_fixed"]:
                                # Update outputs with AI-repaired results
                                stdout_output = result["new_stdout"]
                                stderr_output = result["new_stderr"]
                                exit_status = result["new_exit_status"]

                                command_succeeded = True

                                # Preserve the heuristic registry entry for install_success.
                                # This variable is defined at the TOP of the function so it
                                # survives the break and is visible to install_success.
                                heuristic_registry_entry_for_ai_command_success = registry_entry

                                # DO NOT RETURN — returning would exit the entire function.
                                # We break so the idx loop continues and install_success runs.
                                break

                            # ------------------------------------------------------------
                            # CASE B: AI FAILED TO FIX THE HEURISTIC FAILURE
                            # ------------------------------------------------------------
                            # Attach AI metadata and tags for forensic/telemetry purposes,
                            # then close SSH and return the registry entry as a failure.
                            ai_meta, ai_tags = _build_ai_metadata_and_tags()
                            registry_entry["ai_metadata"] = ai_meta
                            registry_entry["tags"].extend(ai_tags)

                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Unexpected stderr — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue





                    ##### Continue the module2 splice into module2f ###### 
                    ##### BLOCK5(5) Command succeeded default.

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

                    ##### end the module2 splice into module2f #######




                    ######## COMMENT OUT THE AI/MCP HOOK HERE AND USE THE HELPER FUNCTION _invoke_ai_hook ###########
                    ######## This permits us to reuse the AI/MCP HOOK in all the heuristic failure registry_entrys as 
                    ######## well to cover all of the heuristic command failure scenarios with AI/MCP assistance.
                    ######## Covers both strace and non-strace wrapped commands.
                    if exit_status != 0 and attempt == RETRY_LIMIT - 1:
                        # ------------------------------------------------------------
                        # AI/MCP HOOK (via helper)
                        # ------------------------------------------------------------
                        
                        # Normalize extra_tags for the top-level hook so the hook always receives a list.
                        # Include base_tags for telemetry consistency and dedupe while preserving order.
                        #- `dict.fromkeys(...)` preserves order and removes duplicates (Python 3.7+).  
                        #- If `base_tags` is always defined, the `or []` guards are harmless but optional.  
                        #- This keeps the top‑level hook consistent with the heuristic calls that pass `registry_entry["tags"]`.

                        extra_tags_for_hook = list(dict.fromkeys((base_tags or []) + (extra_tags or [])))

                        result = _invoke_ai_hook(
                            original_command=original_command,
                            stdout_output=stdout_output,
                            stderr_output=stderr_output,
                            exit_status=exit_status,
                            attempt=attempt,
                            instance_id=instance_id,
                            ip=ip,
                            extra_tags=extra_tags_for_hook,
                            ssh=ssh
                        )

                        #result = _invoke_ai_hook(
                        #    original_command=original_command,
                        #    stdout_output=stdout_output,
                        #    stderr_output=stderr_output,
                        #    exit_status=exit_status,
                        #    attempt=attempt,
                        #    instance_id=instance_id,
                        #    ip=ip,
                        #    extra_tags=extra_tags,
                        #    ssh=ssh
                        #)

                        # If AI fixed the command → mark success and break out of attempt loop
                        if result["ai_fixed"]:
                            stdout_output = result["new_stdout"]
                            stderr_output = result["new_stderr"]
                            exit_status = result["new_exit_status"]
                            command_succeeded = True
                            break

                        # If AI ran but failed → allow native logic to classify failure normally
                        # (install_failed block below will run because command_succeeded still set to False)
                        stdout_output = result["new_stdout"]
                        stderr_output = result["new_stderr"]
                        exit_status = result["new_exit_status"]



                    ## Commented out original inline AI/MCP HOOK that was inline and ported it to the helper function 
                    ## _invoke_ai_hook
                    ##### Insert AI/MCP HOOK HERE before the except block below ####

                    ## ------------------------------------------------------------
                    ## AI/MCP HOOK — ONLY ON FINAL FAILED ATTEMPT
                    ## ------------------------------------------------------------
                    ## Conditions for invoking AI:
                    ##   • exit_status != 0  → command failed
                    ##   • attempt == RETRY_LIMIT - 1 → this is the FINAL retry
                    ##   • stderr/whitelist logic above has already run
                    ##   • module2f is about to classify this as install_failed
                    ##
                    ## This is the LAST CHANCE before module2f gives up.
                    ## ------------------------------------------------------------
                    #if exit_status != 0 and attempt == RETRY_LIMIT - 1:

                    #    # --------------------------------------------------------
                    #    # 1. Build the AI context payload
                    #    # --------------------------------------------------------
                    #    # This captures EVERYTHING the AI needs to reason:
                    #    #   - command that failed
                    #    #   - stdout/stderr
                    #    #   - exit status
                    #    #   - retry count
                    #    #   - instance metadata
                    #    #   - OS info (if available)
                    #    #   - command history (if available)
                    #    #   - original module2e tags (extra_tags)
                    #    #
                    #    # NOTE: These variables (os_info, command_history, extra_tags)
                    #    #       must already exist in module2f or be set to None.
                    #    # --------------------------------------------------------
                    #    context = {
                    #        "command": original_command,
                    #        "stdout": stdout_output,
                    #        "stderr": stderr_output,
                    #        "exit_status": exit_status,
                    #        "attempt": attempt + 1,
                    #        "instance_id": instance_id,
                    #        "ip": ip,
                    #        "tags": extra_tags,
                    #        "os_info": globals().get("os_info", None),
                    #        "history": globals().get("command_history", None),
                    #    }

                    #    # --------------------------------------------------------
                    #    # 2. Call the AI Gateway Service through the MCP client
                    #    # --------------------------------------------------------
                    #    # ask_ai_for_recovery() → MCPClient.send() → POST /recover
                    #    # The AI Gateway forwards context to the LLM and returns a plan.
                    #    # --------------------------------------------------------
                    #    print(f"AI_MCP_HOOK[{ip}] 🔍 Invoking AI/MCP recovery engine...")
                    #    plan = ask_ai_for_recovery(context)
                    #    # The ask_ai_for_recovery function is defined inside the MCP Client (AI Request Sender block) that is
                    #    # at the top of this module2f.   
                    #    # The AI Request Sender block uses the my_mcp_client.py Class definition so that mcp.send(context) can
                    #    # be forwarded to teh AI Gateway service that is running locally on port 8000. The AI Gateway service
                    #    # then forwards the context to the AI/LLM for consultation and a plan.


                    #    # --------------------------------------------------------
                    #    # 3. Record AI invocation for tagging later
                    #    # --------------------------------------------------------
                    #    ai_invoked = True
                    #    ai_context = context
                    #    ai_plan = plan

                    #    # --------------------------------------------------------
                    #    # 4. Detect fallback conditions
                    #    # --------------------------------------------------------
                    #    # The MCP client returns:
                    #    #   {"error": "...", "action": "fallback"}
                    #    # when:
                    #    #   - AI Gateway is down
                    #    #   - HTTP error
                    #    #   - timeout
                    #    #   - invalid JSON
                    #    #
                    #    # In fallback mode:
                    #    #   • DO NOT apply any plan
                    #    #   • Continue with native module2f logic
                    #    # --------------------------------------------------------
                    #    if plan is None or plan.get("action") == "fallback" or "error" in plan:
                    #        print(f"AI_MCP_HOOK[{ip}] ⚠️ AI fallback triggered — continuing with native logic.")
                    #        ai_fallback = True
                    #        # DO NOT return here — allow module2f to classify failure normally
                    #        # (the install_failed block below will tag ai_fallback)
                    #    else:
                    #        # ----------------------------------------------------
                    #        # 5. AI returned a valid plan — apply it
                    #        # ----------------------------------------------------
                    #        action = plan.get("action")
                    #        print(f"AI_MCP_HOOK[{ip}] 🤖 AI plan received: action={action}")

                    #        # ----------------------------------------------------
                    #        # ACTION: cleanup_and_retry
                    #        # ----------------------------------------------------
                    #        if action == "cleanup_and_retry":
                    #            cleanup_cmds = plan.get("cleanup", [])
                    #            retry_cmd = plan.get("retry")

                    #            # Track commands for tagging
                    #            ai_commands.extend(cleanup_cmds)
                    #            if retry_cmd:
                    #                ai_commands.append(retry_cmd)

                    #            # ------------------------------------------------
                    #            # 5A. Run cleanup commands
                    #            # ------------------------------------------------
                    #            for ccmd in cleanup_cmds:
                    #                print(f"AI_MCP_HOOK[{ip}] 🧹 AI cleanup: {ccmd}")
                    #                cin, cout, cerr = ssh.exec_command(ccmd, timeout=60)
                    #                cout.channel.settimeout(WATCHDOG_TIMEOUT)
                    #                cerr.channel.settimeout(WATCHDOG_TIMEOUT)
                    #                _co, _cs = read_output_with_watchdog(cout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    #                _eo, _es = read_output_with_watchdog(cerr, "STDERR", ip, WATCHDOG_TIMEOUT)

                    #            # ------------------------------------------------
                    #            # 5B. Run retry command
                    #            # ------------------------------------------------
                    #            if retry_cmd:
                    #                print(f"AI_MCP_HOOK[{ip}] 🔁 AI retry: {retry_cmd}")
                    #                rin, rout, rerr = ssh.exec_command(retry_cmd, timeout=60)
                    #                rout.channel.settimeout(WATCHDOG_TIMEOUT)
                    #                rerr.channel.settimeout(WATCHDOG_TIMEOUT)

                    #                r_stdout, _ = read_output_with_watchdog(rout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    #                r_stderr, _ = read_output_with_watchdog(rerr, "STDERR", ip, WATCHDOG_TIMEOUT)
                    #                r_exit = rout.channel.recv_exit_status()

                    #                print(f"AI_MCP_HOOK[{ip}] AI retry exit={r_exit}")

                    #                # ------------------------------------------------
                    #                # 5C. Re-evaluate success using SAME logic as module2f
                    #                # ------------------------------------------------
                    #                if r_exit == 0 and not r_stderr.strip():
                    #                    print(f"AI_MCP_HOOK[{ip}] 🎉 AI successfully repaired the command!")
                    #                    command_succeeded = True
                    #                    break  # break out of attempt loop
                    #                else:
                    #                    print(f"AI_MCP_HOOK[{ip}] ❌ AI retry failed — falling back to native logic.")
                    #                    # DO NOT break — allow module2f to classify failure normally

                    #        # ----------------------------------------------------
                    #        # ACTION: retry_with_modified_command
                    #        # ----------------------------------------------------
                    #        elif action == "retry_with_modified_command":
                    #            new_cmd = plan.get("retry")
                    #            if new_cmd:
                    #                ai_commands.append(new_cmd)
                    #                print(f"AI_MCP_HOOK[{ip}] 🔁 AI modified retry: {new_cmd}")

                    #                rin, rout, rerr = ssh.exec_command(new_cmd, timeout=60)
                    #                rout.channel.settimeout(WATCHDOG_TIMEOUT)
                    #                rerr.channel.settimeout(WATCHDOG_TIMEOUT)

                    #                r_stdout, _ = read_output_with_watchdog(rout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    #                r_stderr, _ = read_output_with_watchdog(rerr, "STDERR", ip, WATCHDOG_TIMEOUT)
                    #                r_exit = rout.channel.recv_exit_status()

                    #                if r_exit == 0 and not r_stderr.strip():
                    #                    print(f"AI_MCP_HOOK[{ip}] 🎉 AI modified command succeeded!")
                    #                    command_succeeded = True
                    #                    break
                    #                else:
                    #                    print(f"AI_MCP_HOOK[{ip}] ❌ AI modified retry failed — falling back to native logic.")

                    #        # ----------------------------------------------------
                    #        # ACTION: abort
                    #        # ----------------------------------------------------
                    #        elif action == "abort":
                    #            print(f"AI_MCP_HOOK[{ip}] 🛑 AI instructed abort — tagging failure.")
                    #            ai_commands.append("abort")
                    #            # Let module2f classify failure normally

                    #        # ----------------------------------------------------
                    #        # Unknown action
                    #        # ----------------------------------------------------
                    #        else:
                    #            print(f"AI_MCP_HOOK[{ip}] ⚠️ Unknown AI action '{action}' — ignoring plan.")
                    #            ai_fallback = True
                    #            # Continue with native logic

                    ## ------------------------------------------------------------
                    ## END OF AI/MCP HOOK
                    ## ------------------------------------------------------------




                # This is an exception within the for attempt loop for a command for the try block inside of the for attempt loop
                #except Exception as e:
                #    print(f"[{ip}] Exception during exec_command: {e}")
                #    registry_entry = {
                #        "status": "install_failed",
                #        "attempt": -1,
                #        "pid": multiprocessing.current_process().pid,
                #        "thread_id": threading.get_ident(),
                #        "thread_uuid": thread_uuid,
                #        "public_ip": ip,
                #        "private_ip": private_ip,
                #        "timestamp": str(datetime.utcnow()),
                #        "tags": base_tags + [
                #            "install_for_attempt_loop_abort",
                #            f"exception_{type(e).__name__}",
                #            command,
                #            f"command_retry_{attempt + 1}"
                #        ]
                #    }
                #    ssh.close()
                #    return ip, private_ip, registry_entry
             
                # This is an exception within the for-attempt loop for a command
                # for the try block inside of the for-attempt loop (POST-HOOK)
                except Exception as e:
                    print(f"[{ip}] Exception during exec_command: {e}")

                    # AI/MCP tag and ai_meta integration
                    ai_meta, ai_tags = _build_ai_metadata_and_tags()  # AI/MCP helper function

                    registry_entry = {
                        "status": "install_failed",
                        "attempt": -1,
                        "pid": multiprocessing.current_process().pid,
                        "thread_id": threading.get_ident(),
                        "thread_uuid": thread_uuid,
                        "public_ip": ip,
                        "private_ip": private_ip,
                        "timestamp": str(datetime.utcnow()),
                        "ai_metadata": ai_meta,  # AI/MCP integration
                        "tags": base_tags + [
                            "install_for_attempt_loop_abort",
                            f"exception_{type(e).__name__}",
                            command,
                            f"command_retry_{attempt + 1}"
                        ] + ai_tags,  # AI/MCP integration
                    }

                    ssh.close()
                    return ip, private_ip, registry_entry



            #### End of for attempt loop


            # If retry loop exhausted without success, tag fail
            # If it gets here then the command failed and one command failed is an install_failed.


            #if not command_succeeded:
            #    registry_entry = {
            #        "status": "install_failed",
            #        "attempt": -1,
            #        "pid": multiprocessing.current_process().pid,
            #        "thread_id": threading.get_ident(),
            #        "thread_uuid": thread_uuid,
            #        "public_ip": ip,
            #        "private_ip": private_ip,
            #        "timestamp": str(datetime.utcnow()),
            #        "tags": base_tags + [f"install_failed_command_{idx}", original_command]
            #    }
            #    ssh.close()
            #    return ip, private_ip, registry_entry
            
            # AI/MCP tag and ai_meta integration
            if not command_succeeded:
                ai_meta, ai_tags = _build_ai_metadata_and_tags()  # AI/MCP helper function
                registry_entry = {
                    "status": "install_failed",
                    "attempt": -1,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "ai_metadata": ai_meta,  # AI/MCP integration
                    "tags": base_tags + [
                        f"install_failed_command_{idx}",
                        original_command
                    ] + ai_tags,  # AI/MCP integration
                }
                ssh.close()
                return ip, private_ip, registry_entry




        ##### End of the for idx loop

        ## All commands succeeded
        ## If it gets this far then the for attempt loops iterated all the way through without failure and all of the commands 
        ## succeeded over all the for idx commands. This is an install_success for the node.

        #transport = ssh.get_transport()
        #if transport:
        #    transport.close()
        #ssh.close()

        #registry_entry = {
        #    "status": "install_success",
        #    "attempt": 0,
        #    "timestamp": str(datetime.utcnow()),
        #    "pid": multiprocessing.current_process().pid,
        #    "thread_id": threading.get_ident(),
        #    "thread_uuid": thread_uuid,
        #    "public_ip": ip,
        #    "private_ip": private_ip,
        #    "tags": base_tags + ["installation_completed"] + ([non_shell_failure_tag] if non_shell_failure_tag else [])
        #}
        #return ip, private_ip, registry_entry



        # All commands succeeded
        # If it gets this far then the for attempt loops iterated all the way through without failure and all of the commands 
        # succeeded over all the for idx commands. This is an install_success for the node.


        ## COMMENT out this block for the AI/MCP refactored block further below
        #transport = ssh.get_transport()
        #if transport:
        #    transport.close()
        #ssh.close()

        ## AI/MCP tag and ai_meta integration
        #ai_meta, ai_tags = _build_ai_metadata_and_tags()  # AI/MCP helper function

        #registry_entry = {
        #    "status": "install_success",
        #    "attempt": 0,
        #    "timestamp": str(datetime.utcnow()),
        #    "pid": multiprocessing.current_process().pid,
        #    "thread_id": threading.get_ident(),
        #    "thread_uuid": thread_uuid,
        #    "public_ip": ip,
        #    "private_ip": private_ip,
        #    "ai_metadata": ai_meta,  # AI/MCP integration
        #    "tags": base_tags + ["installation_completed"] + (
        #        [non_shell_failure_tag] if non_shell_failure_tag else []
        #    ) + ai_tags,  # AI/MCP integration
        #}

        #return ip, private_ip, registry_entry





        # -------------------------------------------------------------------------
        # INSTALL SUCCESS BLOCK with AI/MCP refactoring for heuristic failures
        # -------------------------------------------------------------------------
        # If execution reaches this point, then:
        #   - All commands in all idx iterations have succeeded, OR
        #   - A heuristic failure occurred but AI successfully repaired it and the
        #     retry-for-idx loop continued normally (meaning all commands in all
        #     idx iterations ultimately succeeded).
        # IMPORTANT:
        #   - If AI repaired a heuristic failure, the variable
        #       heuristic_registry_entry_for_ai_command_success
        #     will contain the ORIGINAL heuristic registry entry (with its tags).
        #   - We must merge those heuristic tags into the final install_success
        #     registry entry to preserve full forensic lineage.
        #   - The main objective is to preserve the forensic lineage of the original
        #     heuristic failure after AI/MCP repair.
        # -------------------------------------------------------------------------

        transport = ssh.get_transport()
        if transport:
            transport.close()
        ssh.close()

        # Pull AI metadata and AI tags from persistent state
        ai_meta, ai_tags = _build_ai_metadata_and_tags()

        # Start building the merged tag list
        merged_tags = base_tags + ["installation_completed"]

        # Preserve non-shell failure tag if present
        if non_shell_failure_tag:
            merged_tags.append(non_shell_failure_tag)

        # -------------------------------------------------------------------------
        # Merge heuristic tags IF AND ONLY IF:
        #   - A heuristic failure occurred, AND
        #   - AI successfully repaired it (meaning we broke out of the retry loop),
        #   - AND the heuristic registry entry was preserved earlier.
        # -------------------------------------------------------------------------
        if heuristic_registry_entry_for_ai_command_success:
            merged_tags.extend(
                heuristic_registry_entry_for_ai_command_success.get("tags", [])
            )

        # Always append AI tags last
        merged_tags.extend(ai_tags)

        registry_entry = {
            "status": "install_success",
            "attempt": 0,
            "timestamp": str(datetime.utcnow()),
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "ai_metadata": ai_meta,
            "tags": merged_tags,
        }

        return ip, private_ip, registry_entry






    #### end of the try block



    ## This is an except block for the try block that has both for idx loop and for attempt retry loop.
    #except Exception as e:
    #    try:
    #        ssh.close()
    #    except Exception:
    #        pass
    #    registry_entry = {
    #        "status": "install_failed",
    #        "attempt": -1,
    #        "pid": multiprocessing.current_process().pid,
    #        "thread_id": threading.get_ident(),
    #        "thread_uuid": thread_uuid,
    #        "public_ip": ip,
    #        "private_ip": private_ip,
    #        "timestamp": str(datetime.utcnow()),
    #        "tags": base_tags + ["resurrection_unhandled_exception", type(e).__name__]
    #    }
    #    return ip, private_ip, registry_entry


    # This is an except block for the try block that has both the for-idx loop and the for-attempt retry loop.
    except Exception as e:
        try:
            ssh.close()
        except Exception:
            pass

        # AI/MCP tag and ai_meta integration
        ai_meta, ai_tags = _build_ai_metadata_and_tags()  # AI/MCP helper function

        registry_entry = {
            "status": "install_failed",
            "attempt": -1,
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "timestamp": str(datetime.utcnow()),
            "ai_metadata": ai_meta,  # AI/MCP integration
            "tags": base_tags + [
                "resurrection_unhandled_exception",
                type(e).__name__
            ] + ai_tags,  # AI/MCP integration
        }

        return ip, private_ip, registry_entry


##### end of def resurrection_install_tomcat



####### orchestrator code: this code takes in the resurrection_module2e_registry.json which is already gatekeeper resurrect filtered
####### (all the threads will be attempted to be resurrected), and extracts out the fields necessary for the 
####### resurrection_install_tomcat() arguments.   It also has logic to extract some of the args live with helper functions (for 
####### example, the instance_id). Once it has the args it can run the resurrection_install_tomcat() function on each of the threads
####### in the module2e registry json file, and then output a json file on whether or not the resurrection was successful. 
####### There is some primitive fall back and error logic in there as well which will be expanded once this prototype is up and running.
####### Note the specific test is a thread futures crash in idx1 right after the first command (of 5 here) is successfully executed.
####### Thus the node does not have a successful installation at the time of the crash. Once the thread is resurrected and the commands
####### are re-executed on the node, the node can be empirically tested via an SSH to see of the service(s) are actually running.

LOG_DIR = "/aws_EC2/logs"

#MODULE2E_FILE = "resurrection_module2e_registry.json"

#### For multi-threaded version we need to use the post processed module2e json file where the registry_entrys designated for reboot prior to resurrection have
#### been attempted reboot and the registry_entrys have the reboot_context tags now.  There will no longer be a ghost_context reboot tag used. The reboot_context
#### will cover several different scenarios. Rebooting is now decoupled from the handlers such as process_ghost, so there is no longer a ghost_context reboot.
MODULE2E_FILE = "resurrection_module2e_registry_rebooted.json"




def load_module2e_registry(path=os.path.join(LOG_DIR, MODULE2E_FILE)):
    """
    Load the resurrection candidates from module2e.
    If the file is missing or empty, return {} and print a clear message.
    """
    if not os.path.exists(path):
        print(f"[module2f] No module2e registry found at {path}. Nothing to resurrect.")
        return {}
    with open(path, "r") as f:
        data = json.load(f)
    if not data:
        print(f"[module2f] module2e registry is empty. Skipping resurrection.")
    return data



## See utils.py file
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
#
#def _extract_instance_id(describe_resp):
#    """
#    Helper to pull InstanceId out of AWS describe_instances response.
#    """
#    for r in describe_resp.get("Reservations", []):
#        for i in r.get("Instances", []):
#            iid = i.get("InstanceId")
#            if iid: return iid
#    return None




def get_watchdog_timeout_default():
    """
    For resurrection runs we use a simple baseline timeout.
    Adaptive per-process timeouts from module2 are not strictly needed here.
    """
    return 90


###### serialized version of the main() orchestrator


#def main():
#    registry = load_module2e_registry()
#    if not registry:
#        return
#
#    timeout = get_watchdog_timeout_default()
#    region = os.getenv("region_name")
#
#    results = {}
#    for uuid, entry in registry.items():
#        ip = entry.get("public_ip")
#        private_ip = entry.get("private_ip")
#        replayed_commands = entry.get("replayed_commands", [])
#        extra_tags = entry.get("tags", [])
#        res_uuid = uuid
#
#        # Reuse the original PID from module2e for forensic continuity
#        pid = entry.get("pid", os.getpid())
#
#        # InstanceId logic:
#        # - If module2e already carried instance_id, use it.
#        # - Otherwise, resolve live from AWS by IP.
#        instance_id = entry.get("instance_id")
#        if not instance_id:
#            instance_id = resolve_instance_id(public_ip=ip, private_ip=private_ip, region=region)
#
#        if not instance_id:
#            # If we still can't resolve, skip safely with a stub tag.
#            print(f"[module2f] Skipping {ip} (UUID {uuid}): missing InstanceId.")
#            results[uuid] = {
#                "status": "stub",
#                "attempt": -1,
#                "pid": pid,
#                "thread_uuid": uuid,
#                "public_ip": ip,
#                "private_ip": private_ip,
#                "timestamp": datetime.utcnow().isoformat(),
#                "tags": ["stub", "missing_instance_id"] + extra_tags
#            }
#            continue
#
#        try:
#            
#            # === [LOG ADDITION] Start of resurrection for this node ===
#            print(f"[module2f][INFO] Starting resurrection for InstanceID={instance_id}, PublicIP={ip}")
#
#            ip_out, priv_out, reg = resurrection_install_tomcat(
#                ip=ip,
#                private_ip=private_ip,
#                instance_id=instance_id,
#                WATCHDOG_TIMEOUT=timeout,
#                replayed_commands=replayed_commands,
#                key_path=os.getenv("key_path", "EC2_generic_key.pem"),
#                username=os.getenv("username", "ubuntu"),
#                port=int(os.getenv("port", "22")),
#                max_ssh_attempts=int(os.getenv("max_ssh_attempts", "5")),
#                res_uuid=res_uuid,
#                extra_tags=extra_tags
#            )
#            
#
#            # === [LOG ADDITION] Completion of resurrection for this node ===
#            print(f"[module2f][INFO] Completed resurrection for InstanceID={instance_id}, PublicIP={ip} → Status={reg['status']}")
#
#            # Ensure PID continuity in the registry entry
#            reg["pid"] = pid
#            results[uuid] = reg
#        except Exception as e:
#            print(f"[module2f] Resurrection failed for {ip} (UUID {uuid}): {e}")
#            results[uuid] = {
#                "status": "install_failed",
#                "attempt": -1,
#                "pid": pid,
#                "thread_uuid": uuid,
#                "public_ip": ip,
#                "private_ip": private_ip,
#                "timestamp": datetime.utcnow().isoformat(),
#                "tags": ["install_failed", "module2f_exception", type(e).__name__] + extra_tags
#            }
#
#    # Persist results to disk
#    out_path = os.path.join(LOG_DIR, "module2f_resurrection_results.json")
#    with open(out_path, "w") as f:
#        json.dump(results, f, indent=2)
#    print(f"[module2f] Wrote resurrection results to {out_path}")
#
#if __name__ == "__main__":
#    main()



###### Multi-threaded version of the main() orchestrator



from concurrent.futures import ThreadPoolExecutor, as_completed

def main():
    registry = load_module2e_registry()
    if not registry:
        return

    timeout = get_watchdog_timeout_default()
    region = os.getenv("region_name")

    results = {}

    # === ThreadPool harness ===
    with ThreadPoolExecutor(max_workers=16) as executor:  # adjust workers as needed: 4 and 8 and 16 for 16 node test 
        future_map = {}

        for uuid, entry in registry.items():
            ip = entry.get("public_ip")
            private_ip = entry.get("private_ip")
            replayed_commands = entry.get("replayed_commands", [])
            extra_tags = entry.get("tags", []) # extra_tags is used to carry over the original tags from the previous module2e import
            res_uuid = uuid

            # Reuse the original PID from module2e for forensic continuity
            pid = entry.get("pid", os.getpid())

            # InstanceId logic:
            instance_id = entry.get("instance_id")
            if not instance_id:
                instance_id = resolve_instance_id(public_ip=ip, private_ip=private_ip, region=region)
 
            # version1 of module2f:
            #if not instance_id:
            #    # If we still can't resolve, skip safely with a stub tag.
            #    print(f"[module2f] Skipping {ip} (UUID {uuid}): missing InstanceId.")
            #    results[uuid] = {
            #        "status": "stub",
            #        "attempt": -1,
            #        "pid": pid,
            #        "thread_uuid": uuid,
            #        "public_ip": ip,
            #        "private_ip": private_ip,
            #        "timestamp": datetime.utcnow().isoformat(),
            #        "tags": ["stub", "missing_instance_id"] + extra_tags
            #    }
            #    continue


            # version2 of module2f: If there is no instance_id do not use the continue as above, but let the code flow into the submit future and execute
            # the ThreadPoolExecutor on the node.  It is highly unusual if an AWS node InstanceId cannot be fetched, but with the synthetic ghost injection
            # for code testing, this is in fact the case. We want the synthetically injected ghost ips to fail "naturally" with an install_failed SSH connect
            # error in the TheadPoolExecutor call to resurrection_install_tomcat rather than stub the entry as above. The stub code block is commented out for
            # this reason. In addtion tag the registry_entry accordingly with missing_instance_ip
            if not instance_id:
                print(f"[module2f] Proceeding without InstanceId for {ip} (UUID {uuid}). Will attempt SSH and log clean failure if any.")
                extra_tags = (extra_tags or []) + ["missing_instance_id"]
                # do not use a continue after this. Let the code flow into the ThreadPoolExecutor call to resurrection_install_tomcat below.




            # === [LOG ADDITION] Start of resurrection for this node ===
            print(f"[module2f][INFO] Starting resurrection for InstanceID={instance_id}, PublicIP={ip}")

            # Submit task to thread pool
            future = executor.submit(
                resurrection_install_tomcat,
                ip, private_ip, instance_id, timeout, replayed_commands,
                key_path=os.getenv("key_path", "EC2_generic_key.pem"),
                username=os.getenv("username", "ubuntu"),
                port=int(os.getenv("port", "22")),
                max_ssh_attempts=int(os.getenv("max_ssh_attempts", "5")),
                res_uuid=res_uuid,
                extra_tags=extra_tags #send the original tags to the function resurrection_instalL_tomcat with extra_tags arg
            )
            future_map[future] = (uuid, pid, ip, private_ip, instance_id, extra_tags)

        # Collect results as threads finish
        for future in as_completed(future_map):
            uuid, pid, ip, private_ip, instance_id, extra_tags = future_map[future]
            try:
                ip_out, priv_out, reg = future.result()

                # === [LOG ADDITION] Completion of resurrection for this node ===
                print(f"[module2f][INFO] Completed resurrection for InstanceID={instance_id}, PublicIP={ip} → Status={reg['status']}")

                # Ensure PID continuity in the registry entry
                reg["pid"] = pid
                results[uuid] = reg
            

            # when this exception hits  with a synthetic ghost ip it is because:
            #- The ghost threads timed out inside `resurrection_install_tomcat`.
            #- That exception propagated out of the function without building a registry entry.
            #- The `Future` is now marked **finished with an exception**.
            #- `as_completed` yields it immediately. (the for block above)
            #- The call to `future.result()`, Python re‑raises the exception that was stored in the `Future`.
            #- This `try/except` block in main() is then hit — not because the future is still running, but because it finished *unsuccessfully*.

            except Exception as e:
                print(f"[module2f] Resurrection failed for {ip} (UUID {uuid}): {e}")
                tags = ["install_failed", "module2f_exception", type(e).__name__] + extra_tags
                if instance_id is None:
                    tags.append("no_instance_id_context")   # ensure ghost context survives if there is a timeout in the resurrection_install_tomcat
                results[uuid] = {
                    "status": "install_failed",
                    "attempt": -1,
                    "pid": pid,
                    "thread_uuid": uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": datetime.utcnow().isoformat(),
                    "tags": tags
                }


            #except Exception as e:
            #    print(f"[module2f] Resurrection failed for {ip} (UUID {uuid}): {e}")
            #    results[uuid] = {
            #        "status": "install_failed",
            #        "attempt": -1,
            #        "pid": pid,
            #        "thread_uuid": uuid,
            #        "public_ip": ip,
            #        "private_ip": private_ip,
            #        "timestamp": datetime.utcnow().isoformat(),
            #        "tags": ["install_failed", "module2f_exception", type(e).__name__] + extra_tags
            #    }




    # Persist results to disk
    out_path = os.path.join(LOG_DIR, "module2f_resurrection_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[module2f] Wrote resurrection results to {out_path}")



    # === NEW: Resurrection statistics summary ===
    resurrected_success = sum(1 for r in results.values() if r["status"] == "install_success")
    resurrected_failed = sum(1 for r in results.values() if r["status"] == "install_failed")
    resurrected_stub = sum(1 for r in results.values() if r["status"] == "stub")

    stats = {
        "resurrected_total_threads": len(results),
        "resurrected_install_success": resurrected_success,
        "resurrected_install_failed": resurrected_failed,
        "resurrected_stub": resurrected_stub,
        "resurrected_unique_seen_ips": sorted({r["public_ip"] for r in results.values()}),
        "resurrection_success_rate_percent": (
            100.0 * resurrected_success / len(results) if results else 0.0
        )
    }

    stats_dir = os.path.join(LOG_DIR, "statistics")
    os.makedirs(stats_dir, exist_ok=True)
    stats_path = os.path.join(stats_dir, "aggregate_resurrected_node_stats_module2f.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"[module2f] Wrote resurrection stats to {stats_path}")



if __name__ == "__main__":
    main()

