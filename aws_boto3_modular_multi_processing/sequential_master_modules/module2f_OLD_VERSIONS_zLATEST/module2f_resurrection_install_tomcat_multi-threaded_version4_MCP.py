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


    #### END of the for attempt in range(5) block #####







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

                    # Known heuristic: apt missing package strings (kept minimal here)
                    if "E: Package 'tomcat9'" in stderr_output:
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
                                    "fatal_package_missing",
                                    command,
                                    f"command_retry_{attempt + 1}",
                                    *stderr_output.strip().splitlines()[:12]
                                ]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
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
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] Non-zero exit — retrying...")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

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
                                    "stderr_detected",
                                    command,
                                    f"command_retry_{attempt + 1}",
                                    "exit_status_zero",
                                    "non_whitelisted_stderr",
                                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],
                                    *stderr_output.strip().splitlines()[:25]
                                ]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] Unexpected stderr — retrying...")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

                    # Success
                    command_succeeded = True
                    time.sleep(5)  # keep this short in resurrection
                    break

                # This is an exception within the for attempt loop for a command for the try block inside of the for attempt loop
                except Exception as e:
                    print(f"[{ip}] Exception during exec_command: {e}")
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
                            "install_for_attempt_loop_abort",
                            f"exception_{type(e).__name__}",
                            command,
                            f"command_retry_{attempt + 1}"
                        ]
                    }
                    ssh.close()
                    return ip, private_ip, registry_entry
             



            #### End of for attempt loop


            # If retry loop exhausted without success, tag fail
            # If it gets here then the command failed and one command failed is an install_failed.


            if not command_succeeded:
                registry_entry = {
                    "status": "install_failed",
                    "attempt": -1,
                    "pid": multiprocessing.current_process().pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": base_tags + [f"install_failed_command_{idx}", original_command]
                }
                ssh.close()
                return ip, private_ip, registry_entry


        ##### End of the for idx loop

        # All commands succeeded
        # If it gets this far then the for attempt loops iterated all the way through without failure and all of the commands 
        # succeeded over all the for idx commands. This is an install_success for the node.

        transport = ssh.get_transport()
        if transport:
            transport.close()
        ssh.close()

        registry_entry = {
            "status": "install_success",
            "attempt": 0,
            "timestamp": str(datetime.utcnow()),
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "tags": base_tags + ["installation_completed"] + ([non_shell_failure_tag] if non_shell_failure_tag else [])
        }
        return ip, private_ip, registry_entry




    #### end of the try block



    # This is an except block for the try block that has both for idx loop and for attempt retry loop.
    except Exception as e:
        try:
            ssh.close()
        except Exception:
            pass
        registry_entry = {
            "status": "install_failed",
            "attempt": -1,
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip,
            "timestamp": str(datetime.utcnow()),
            "tags": base_tags + ["resurrection_unhandled_exception", type(e).__name__]
        }
        return ip, private_ip, registry_entry






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

