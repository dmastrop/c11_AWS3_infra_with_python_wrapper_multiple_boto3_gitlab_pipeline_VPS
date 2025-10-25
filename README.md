#  System Resilience Engineering | High-Concurrency Diagnostic Design in Python:
## Adaptive Resurrection Pipelines: Artifact Rehydration and Ghost Trace Detection in Distributed Debugging Systems


```
```


## Current and latest development work


The parent directory has the Docker files and the gitlab-ci.yml file
Dockerfile_python_multi_processing is for the latest development gitlab pipeline.

The .env file on the docker container is dynamically created at pipeline runtime during the deploy stage
It only exists on the ephemeral docker python container instance that is running the master python script

All python (mastser_script.py) run in self contained Docker container on the VPS

The VPS also hosts a self-managed gitlab container from which the pipelines are run. This expedites the repetitive testing, 
especially for benchmarking the module2 (below).

Latest development work is in the aws_boto3_modular_multi_processing sub-directory
The master_script.py is in this directory

This has all the latest multi-threading and multi-processing code in the sequential_master_modules package(directory)

The current 11 modules in the package sequential_master_modules are multi-processed in the master_script.py

The key module is the "install tomcat"  module (module2 in the master_script.py) in the following directory
aws_boto3_modular_multi_processing/sequential_master_modules
Use the latest timestamp python file.

This has all the latest optimizations for the multi-processing and multi-threading and the latest benchmark upates below
pertain to the optmizations to this module.

The pem key is a generic pem key for all of the ephemeral test EC2 instances. The EC2 instances are terminated after each successive run.





## High level project summary:


System Resilience Engineering | High-Concurrency Diagnostic Design in Python:
Adaptive Resurrection Pipelines: Artifact Rehydration and Ghost Trace Detection in Distributed Debugging Systems



Designed and executed a fault-tolerant parallel testing framework to diagnose silent SSH failures across 800 concurrent processes. Implemented watchdog-retry orchestration and swap profiling to isolate ghost threads with forensic clarity. The system is built in Python with multi-processing and multi-threading support, enabling large-scale application deployment across hundreds of AWS instances as part of a broader infrastructure automation suite.
Testing is performed in a self-hosted GitLab DevOps pipeline using Docker containers to recursively validate resilience, log fidelity, and system behavior under extreme concurrency. 

•Phase 2 – Resurrection Logic : Integrated watchdog and retry-aware monitoring to detect silent thread stalls. Resurrection registry captures failure candidates for postmortem logging and sets the foundation for adaptive thread recovery.

•Phase 3 – Thread Healing & Adaptive Retry: Threads flagged in Phase 2 will be dynamically respawned or rerouted during execution. This includes resurrection monitors, fallback pools, and potential thread override logic tuned to system state and swap conditions.

•Phase 4 – Machine Learning Integration: ML modules will ingest historical resurrection logs and real-time telemetry to predict failure likelihood, tag anomalies, and adjust orchestration. Framework becomes self-tuning—modifying retry logic, watchdog thresholds, and workload routing based on learned failure patterns.


Some features: 

- Thread level registry tagging of ghost threads, failures, stubs, successes 
- Registry tagging for scenario-specific traceability (thread_uuid, status, attempt, timestamp, ip, tags)
- Aggregate and process level orchestration logging for host VPS CPU, swap, and thread level installation status, per process runtime
- Aggregate and process level execution logging for: registries, successful, failure, missing, total, resurrection candidates (Gitlab
artifact logs per pipeline)
- Aggregate gold ip list (AWS orchestration level) logging
- Resurrection monitor logic that differentiates between install failures, stubs, crashes, and ghost threads (ghost detection logic)
- Registry snapshots with thread_uuid lineage and tagging for forensics
- Synthetic edge case injection testing for wrapper brittleness (bash and bash-like commands strace wrapper and injection into STDERR)
- Extensible whitelist command agnostic package installation capability (apt, yum, dnf) with raw output data orchestrator (STDOUT/STDERR)
- Intelligent strace wrapper  override logic for shell PID vs subprocess ambiguity  
- Deterministic artifact lineage across chaotic shell flows
- Forensic triage via non-whitelisted stderr detection 
- Resurrection monitor logic with phase-tagged recovery attempts  
- Cross-platform shell wrapper (strace) resilience with synthetic test injection 
- Adaptive dynamic watchdog timeout for (node) raw output data orchestrator (process level; adaptive to AWS API congestion)
- Adaptive orchestration logic with ML/LLM feedback hooks 





## Latest milestone updates to refer to below:

- Update part 21: Phase 2g: write-to-disk aggregator reviews the architecture of phase2 at a high level

- Update part 22: implementation of adaptive WATCHDOG_TIMEOUT

- Update part 23: implementation of the control plane Public IP orchestrator

- Update part 24: Phase 2h: resurrection_monitor_patch7d1 fix for the ghost json logging fix using instance_info (chunk) for process level GOLD ip list for ghost detection

- Update part 25: Phase 2i: Refactoring the benchmark_ips and benchmark_ips_artifact.log creation in resurrection_monitor_patch7d with a modular function

- Update part 26: Phase 2j: Refactoring the aggregation ghost detection code with the chunks in main() as GOLD standard

- Update part 27: Phase 2k: STUB registry creation for pseudo-ghosts so that they can be tagged as failed and resurrected; also unification of code with thread_uuid for registry indexing

- Update part 28: Phase 2L: Refactoring of the install_tomcat and the read_output_with_watchdog making the code stream agnostic anda general-purpose, resilient command orchestrator that can install any set of commands on the EC2 nodes

- Update part 29: Phase 2m: Refactoring of the read_output_with_watchdog and install_tomcat continued: Whitelist support for apt and bash and bash-like commands, continue making the code stream agnostic and a general-purpose, resilient command orchestrator

- Update part 30: Phase 2n: Refactoring the adaptive watchdog timeout and the API congestion function retry_with_backoff

- Update part 31: Phase 2o: Fixing the empty security_group_ids list with hyper-scaling tests and ensuring that the security group list is chunked as sg_chunk prior to engaging multi-processing.Pool and calling tomcat_worker_wrapper

- Update part 32: Phase 2p: Resurrection code overhaul moving code out of install_tomat() and into resurrection_monitor_patch8, refactoring resurrection monitor, add batch ip re-hydration code for thread futures crashes (tomcat_worker), synthetic thread futures crash injection (testing), resurrection_gatekeeper

- Update part 33 Phase 2q: resurrection_monitor restructuring using helper functions: (1) PROCESS LEVEL ghost detection using chunk for process level GOLD list, and (2) PROCESS level registry stats generation

- Update part 34 Phase 2r: Implemenation of module2b for post ghost analysis using a scan analysis of module2 gitlab console logs (later will be used for ML lifecycle and pattern discernment).




## A note on the STATUS_TAGS:


I added a STATUS_TAGS at the top of the module to track the taxonomy of the various status tags that can be used in 
the registry_entry. All of the status tags below have not been put to use yet.(for example. gatekeeper_resurrection,
watchdog_timeout, no_tags, ssh_initiated_failed).  The ssh_retry_failed, install_failed, install_success, and stub
are currently in use. The registry_entry also has a "tags" field that can be used for other identifying and contextual
information regarding the status. This can be used in forensics when troubleshooting mysterious threads that are not 
behaving properly and can be used by the resurrection_gatekeeper filter logic heuristics when deciding whether or not
a thread (candidate) is viable for actual resurrection.

```
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
```



## UPDATES part 34: Phase 2r: Implemenation of module2b for post ghost analysis using a scan analysis of module2 gitlab console logs (later will be used for ML lifecycle and pattern discernment)

### Introduction:

The greatest challenge with the forensic analysis is in detecting ghosts and then finding out as much information on them as possible
and reporting them in the gitlab artifact logs.

Currently, the only information we have on ghosts is their ip addresses as it is calculated from the delta between the golden ip
list of ips (During AWS orchestration layer) and the seen ips in the aggregate registry (those ips that have an actual thread_uuid
and a PID assigned to them).  

This section details an approach whereby the module2 gitlab console logs will be streamed to a module2b for post ghost analysis. 
From the scan of the gitlab logs, the proces_index (assigned to the ip) and various other characteristics associated with the ip,
can be ascertained from the complete scan.   For starters, the process_index will be identified and a tags field will also be 
created to add other items that are associated with the ip like whether or not the SSH connection was attempted.

The process_index associated with the chunk of data for each process might be useful in Phase3 to try to resurrect even these ghosts, 
by finding out the PID of the process_index and reinitiating the thread from scratch using that designated PID.


### Implementation details:

The implemenation consists of the following:

- Create a new python module file module2b_post_ghost_analysis.py

- Add the new python module to the master_script.py file. All python modules are multi-processed as much as possible (modules that can
be run in parallel can be configured to do so).

- Given that the ghost analysis of the console logs occurs once the module2 logs are complete, the module2b has to be excuted sequentially
rather than in parallel with module2.

- Modify the .gitlab-ci.yml file accoringly to tee all the output of the docker run command to the file below (note the volumne 
mount is already being used for the logging to the pipeline artifact logs):


```
  script:
    - mkdir -p logs
    #- docker run --rm --env-file .env -v $CI_PROJECT_DIR/logs:/aws_EC2/logs $CI_REGISTRY_IMAGE:latest
    # add the tee to get all the gitlab console output into a log file in the gitlab artfacts:
    - docker run --rm --env-file .env -v $CI_PROJECT_DIR/logs:/aws_EC2/logs $CI_REGISTRY_IMAGE:latest | tee logs/gitlab_full_run.log
    - echo "Contents of logs directory after container run:"
    - ls -l logs/
    - echo "Last 10 lines of MAIN logs:"
    - cat logs/main_*.log | tail -10
```


- Use the aggregate_ghost_summary.log, which has the missing ghost ips, as a substrate for the module2b analysis

- In module2b analyze the gitlab_full_run.log that was teed from the docker run command, using streaming rather than buffering of the 
file to read it in.  Grep it for the ips in the aggregate_ghost_summary.log for the post analysis

- Publish the results of the analysis as a gitlab console log file aggregate_ghost_detail.log file


### Code implementation:


The code is all in module2b:

The logic is straight forward.  Stream read the consle log created from the docuer run tee (see .gitlab-ci.yml excerpt above).
Open the aggregate_ghost_summary.log from module2, and use this for the ghost ip grep of the streamed gitlab console logs
While grepping for the ghost ips tag each ghost ip accoringly: ghost if found in the console logs, and whether or not the ssh connection
was attempted. In the future there were be additional tags added as we discover more about the nature of the various ghosts.

A typical ghost signature in the logs is that the ip address appears in only 2 parts as indicated below (this particlar ghost
followed a day after AWS went down for several hours) 


```
TRACE][aggregator] Aggregate GOLD IPs from chunk hydration:
  100.24.47.94
  100.25.216.2  <<<here is the ghost (1 of 14 of them)
And so on....

And you will see this: 
In a long list of all 512 processes (this test has chunk size of 1 thread per process so 512 proceseses) 
[DEBUG] Process 190: chunk size = 1
[DEBUG] Process 190: IPs = ['100.25.216.2']
``` 


The module2b code:

```
#### Post ghost analysis with json file schema 
#- Streams the console log line-by-line (no buffering)
#- Tags ghosts based on absence of expected signals
#-  Detects SSH attempts using `"Attempting to connect to"`
#-  Extracts `process_index` from chunk assignment lines  (NOTE: process_index is not the same as the PID)
#-  Avoids false tagging of stubs by relying on ghost IPs only, otherwise some stubs could be aggregated into this ghost detail json
#-  Includes full error handling and final JSON writeout


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

```

### Synthetic ghost ip injection:


Since ghosts are extremely rare even with hyper-scaling testing (the above code was regression tested with 512 nodes and there was
no ghosts, only an install_failed) synthetic ghost ip injection is required to test the code above to ensure that the 
aggregate_ghost_detail.json file is created correctly.







## UPDATES part 33: Phase 2q: resurrection_monitor restructuring using helper functions: (1) PROCESS LEVEL ghost detection using chunk for process level GOLD list, and (2) PROCESS level registry stats generation


### Introduction:

Currently, the ghost detection code is inline in the module resurrection_monitor_patch8.  This simply moves out that code into
a helper function similar to what was done for the hydrate_benmchmark_ips (deprecated now).    ALso add the PROCESS level 
registry stats to the resurrection_monitor_patch8. This is a per process level statistics of the registry_entry status/tags
for that specific process. This is already done at the aggregate level (post execution write-to-disk) in main() and getting 
the process level stats is trivial (they are already available).




### Code changes:


A small block of code in the resurrection__monitor function was commented out with the followign comment:

```
# 🔒 Legacy ghost/candidate dump logic disabled — replaced by detect_ghosts() in Patch8
# Commented out to prevent redundant artifact writes and confusion during modular refactor
```

This is part of the effort to continue to clean up the resurrection_monitor


This block is commented out as well. This will be populated at the process level with another helper function (note
all of these are also calclated at the aggregate level in main()):


```
 # Summary conclusion: This block will be used with patch 7d2 for process level stats .
            #Patch7_logger.info("🧪 Patch7 reached summary block execution.")
            #Patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
            #Patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
            #Patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
            #Patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
            #Patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
            #Patch7_logger.info(f"Composite alignment passed? {len(missing_registry_ips) + len(total_registry_ips) == len(benchmark_ips)}")

```





## UPDATES part 32: Phase 2p: Resurrection code overhaul moving code out of install_tomat() and into resurrection_monitor_patch8, refactoring resurrection monitor, add batch ip re-hydration code for thread futures crashes (tomcat_worker), synthetic thread futures crash injection (testing), resurrection_gatekeeper



This large update consists of the following sections:

- High level summary of proposed changes for the refactoring
- Implementation strategies
- Code review of the implemenation strategies
- A 512 hyperscaling test with the new code im place following the AWS 10/20/25 outage that detects residual transient instablity at scale



### High level summary of proposed changes: 

#### Stage1:
Remove `update_resurrection_registry`. Resurrection tagging should be completely centralized
- Refactor `read_output_with_watchdog` to return output and status only: `(stdout, stderr, status)` only
- Move all resurrection tagging logic out of `install_tomcat`.
- Let `resurrection_monitor_patch8` handle all resurrection logic based on `process_registry`



#### Stage2:
Move Resurrection Candidate Logic to `resurrection_monitor_patch8` This will be a process level resurrection candidate json
file. There is already an aggregate resurrection candidate json file artifact.

This resurrection candidate process level file will be done from the process_registry:

- Scan `process_registry` in real time for `status != "install_success"`.
- Tag resurrection candidates based on process-level heuristics.
- Eliminate `resurrection_registry` entirely.

Inside `resurrection_monitor_patch8`, scan using the logic !=install_success tentatively (this will cover all stub and
install_failed registry threads, etc.)


```
for thread_uuid, entry in process_registry.items():
    if entry.get("status") != "install_success":
        # Tag as resurrection candidate
```

This eliminates the need for a separate `resurrection_registry` and keeps all resurrection logic in one place.


#### Stage3:
Modularize Resurrection Gatekeeper (currently called from install_tomcat, but it needs to be called from resurrection_monitor)
- Refactor `resurrection_gatekeeper()` to be reusable outside `install_tomcat`.
- Use it in `resurrection_monitor_patch8` to decide which threads to resurrect. Bascially all of the install_failed and most
if not all of the stubs (i.e., not install_success registry_entry threads)
- Filter resurrection candidates
- Decide whether to retry based on tags like `"install_failed"` or `"stub"`
- This sets the stage for Phase3 of this project where the threads will be resurrected.


### Implementation strategies: 

These updates are focused on cleaning up and refactoring the resurrection monitor code.  


#### resurrection_monitor_patch8 function changes:

The resurrection monitor (currently function resurrection_monitor_patch8) is a function that screens the process_registry for each process for 3 basic types of resitry_entry
anomalies. 

The call to the resurrection_monitor_patch8 function is made from tomcat_worker after process_registry for a given process is returned
from a call to run_test which calls threaded_install. There are all process level functions. 

There are 3 code blocks in the resurrection_monitor that are dedicated to these 3 types of anomalies.
1. A ghost detection block
2. An untraceable registry_entry block (These can be mistaken for ghosts but are not ghosts; see "Ghost registry threads" below.
3. A resurrection candidates block. These are all regsitry_entrys that are != install_success (not equal to install_success). This
includes install_failed and stub registry_entrys created using extensive failure detection logis in install_tomcat and 
threaded_install functions.


The order of these code blocks in the resurrection monitor is important, moving from most specific to most general in 
nature.  


 ```
    Ghost detection block 
       - Based on `assigned_ip_set - seen_ips`  
       - Produces `resurrection_ghost_missing_{pid}_{ts}.json`
    
    Untraceable registry entries block
       - Captures registry entries with missing or invalid IPs  
       - Produces `resurrection_untraceable_registry_entries_{pid}_{ts}.json`
    
    Resurrection candidates block  
       - Based on `status != "install_success"`  
       - Produces `resurrection_candidates_registry_{pid}_{ts}.json`
    
     Why this order works:
    - Ghost detection is IP-driven and must come first  
    - Untraceable entries are registry-driven and help explain ghost edge cases  
    - Resurrection candidates are broader and include both traceable and untraceable entries
```

```

    | Artifact Filename Pattern                              | Contents                                  |
    |--------------------------------------------------------|-------------------------------------------|
    | `resurrection_candidates_registry_{ts}.json`           | All non-success registry entries          |
    | `resurrection_ghost_missing_{ts}.json`                 | IPs from chunk not seen in registry       |
    | `resurrection_untraceable_registry_entries_{ts}.json`  | Registry entries with missing/invalid IPs |

```
```
     aggregate counterparts (created in main())
    - `resurrection_ghost_missing_{ts}.json`
    - `resurrection_candidates_registry_{ts}.json`
    - `resurrection_untraceable_registry_entries_{ts}.json`
```
The aggreagation json files are assembled from a write-to-disk re-assembly of all the process_registry sets for all processes in the
execution run. The aggregate registry listing can then be screened and filtered out accordingly by the criteria descirbe in detail
below....

The 3 types of registry anomalies detected by the resurrection monitor are:



1.Ghost registry threads. Ghost threads are threads that are completely missing from the process_registry and thus the aggregate list
of registry_entrys.   They show up in the missing_registry_ips_artifact.log file as a list of missing ip addresses. These are very
rare occurrences. They are determined from an AWS golden list of ip addresses taken from chunk ip data that is fed into the 
multiprocessing.Pool. A chunk is a list of ip addresses (EC2 instances or nodes) that the process is designated to work on.  Each process
is multi-threaded and can have many threads running in it. A thread is always dedicated to a single node.  The chunk ip data serves as
a golden list, and a seen_ips variable tracks the ip addresses that are actually seen in the registry_entrys of the process_registry
(1 registry_entry per thread or node).   Any missing ips in the process_regsitry consititute a probable ghost.   Probable becasue:
these are not alwaysghosts in the technical sense. 

For example,so metimes a thread will have a missing ip address if the thread futures crashes (ThreadPoolWorker). In 
cases like this, the ip address can usually be re-hyrdated, in other workds re-injected back into the affected registry_entry in the 
process_registry, prior to ghost detection in the resurrection monitor. This avoids a ghost misc-classification (missing ip).  
However, there may be instances still yet not observed whereby the ip address in the registry_entry is missing. 
We know the cause (the cause will be in the registry_entry tag field), the thread will have a thread_uuid, and a PID, but no ip address. 
So technically this is not a ghost, but it will be designated a ghost. This has not been observed yet in testing. Normally if an ip address is missing in the registry_entry itself, this means something catostrophic happened and the  thread and registry_entry are not created in 
the process_registry.

Regarding the thread ip re-hydration code. This will be reviewed in detail in this update further below.  A thread that crashes can be
re-hydrated in almost all cases, except of there is a true ghost AND thread crash(es) in the SAME process. This is because the 
threads can no longer be matched up to "missing" ips in that process if there are 1 or more true ghosts. If there are no true ghosts and
the  number of crashed threads = the number of "missing" ips, the threads can be rehydrated deterministically with the "missing" ips.
At that point the registry_entry (thread) is not longer mis-classified as a ghost and will be classified only as install_failed. It 
should be noted that true ghost + thread futures crashes in the SAME process are extremely rare. If these are in separate processes, 
the re-hydration can occur without any issues.

The ghost detection code in the resurrection monitor is designated as BLOCK1: Ghost detection. This will be modularized into a helper function detect_ghosts.

2.Untraceable registry_entrys.  This applies to a registry_entry that has no public or private ip address.  As noted above, this
can happen but it has not been seen in actual testing, except for the thread futures crash, which has been patched with 
ip re-hydration code. It is not known what other causes and cases may exist that may provoke this type of registry_entry.

The untraceable registry_entry code is designated as BLOCk2: Untraceable registry_entrys


3.Resurrection candidates. These are simply all the registry_entrys that are != install_success (not equal to install_success status)
All of these are prime first order resurrection candidates that will try to be revived by the Phase 3 recovery code.

The resurrection candidate code is designated as BLOCK3: Resurrection candidate code.



#### Cleanup of old code related to the resurrection_monitor code

In addition to refactoring the function itself using the 3 blocks above, there was also a lot of cleanup in the supporting functions.

- There was old code in the resurrection_monitor itself that had to be removed.  The resurrection_registry has been replaced with the 
process_registry.  

- install_tomcat, a thread level function, had calls to resurrection_gatekeeper which are no longer required.

- The resurrection_registry_lock had to be removed from the code as there is no longer a resurrection_registry. 

- Other legacy and deprecated code in the resurrection_monitor had to be commented out.



#### The case for ip re-hydration

While running some hyper-scaling testing with 512 nodes (512 concurrent processe), a thread futures crash was occuring fairly consistently
The current code had an unknown public and private ip address in the install_failed registry_entry for each of these threads.
The "unknown" was polluting the ip based process level and aggreagate level logs. In addtion these threads were being classified in the 
ghost logs and the install_failed logs (double counted).   The "unknown" ip addreses had to be re-hyrdrated using the golden orchestration
AWS level list of ips for the given pipeline run. This resolved all of the issues. 

This code change was quite signficant. The re-hydration has to occur at the batch level in tomcat_worker rather than in threaded_install.
The crash registry_entry is actually created in threaded_install with an "unknown" ip address initially. 
Once the process completes, all of the "missing" ip addresses as described in the section above are detrministically assigned to the
registry_entrys with "unknown". These only occur with the futures thread crash. They are no longer mis-classified as ghosts but rather
only install_failed and they are flagged  by the BLOCK3 resurrection candidate code for phase3 resurrection.

The section below on this will review all the code in detail.

#### Collateral effects of the re-hydration

The collateral effects of the re-hydration code were mostly positive. There was one issue where the logger for the process level
benchmark process level logs were getting the "unknown" address simply because the logger was in the threaded_install function still, which
is prior to the re-hydration that occurs in the tomcat_worker function. These both utilize the same python logger and so it was easy to 
place the logger line for the benchmark process level logs inside the for loop of the re-hydration code in tomcat_worker. 
The rest of the logs built from the benchmark process level logs were self corrected, as they are built from the process level logs.

For example prior to the fix the benchmark process level log looked like this even after the re-hydration code for the registry_entry
(prior section above):


```
2025-10-16 01:09:58,819 - 15 - MainThread - Test log entry to ensure file is created.
2025-10-16 01:10:05,658 - 15 - MainThread - [PID 15] START: Tomcat Installation Threaded
2025-10-16 01:10:05,658 - 15 - MainThread - [PID 15] Initial swap usage: 2.30 GB
2025-10-16 01:10:05,658 - 15 - MainThread - [PID 15] Initial CPU usage: 0.00%
2025-10-16 01:12:07,798 - 15 - Thread-5 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-10-16 01:12:08,241 - 15 - Thread-5 - Authentication (publickey) successful!
2025-10-16 01:12:08,243 - 15 - MainThread - [PID 15] [UUID c23f7f19] ❌ Future crashed | Public IP: unknown | Private IP: unknown
2025-10-16 01:12:58,532 - 15 - Thread-8 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-10-16 01:12:58,959 - 15 - Thread-8 - Authentication (publickey) successful!
2025-10-16 01:12:58,960 - 15 - MainThread - [PID 15] [UUID e857badf] ❌ Future crashed | Public IP: unknown | Private IP: unknown
2025-10-16 01:12:59,962 - 15 - MainThread - [PID 15] END: Tomcat Installation Threaded
2025-10-16 01:12:59,962 - 15 - MainThread - [PID 15] Final swap usage: 1.48 GB
2025-10-16 01:12:59,962 - 15 - MainThread - [PID 15] Final CPU usage: 0.00%
2025-10-16 01:12:59,962 - 15 - MainThread - [PID 15] Total runtime: 174.30 seconds
```

After the fix they logs look like this, fully re-hydrated: 
(note RE-hyrdated ip addresses now)

```
2025-10-16 23:47:20,938 - 13 - MainThread - Test log entry to ensure file is created.
2025-10-16 23:47:28,858 - 13 - MainThread - [PID 13] START: Tomcat Installation Threaded
2025-10-16 23:47:28,858 - 13 - MainThread - [PID 13] Initial swap usage: 1.19 GB
2025-10-16 23:47:28,858 - 13 - MainThread - [PID 13] Initial CPU usage: 0.00%
2025-10-16 23:50:01,383 - 13 - Thread-6 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-10-16 23:50:01,396 - 13 - Thread-7 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-10-16 23:50:01,815 - 13 - Thread-6 - Authentication (publickey) successful!
2025-10-16 23:50:01,878 - 13 - Thread-7 - Authentication (publickey) successful!
2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] END: Tomcat Installation Threaded
2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] Final swap usage: 1.19 GB
2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] Final CPU usage: 0.00%
2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] Total runtime: 154.02 seconds

2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] [UUID f7e01e12] ❌ Future crashed | RE-hydrated Public IP: 100.27.189.85 | RE-hydrated Private IP: 172.31.28.141
2025-10-16 23:50:02,881 - 13 - MainThread - [PID 13] [UUID 08725a6d] ❌ Future crashed | RE-hydrated Public IP: 98.91.26.246 | RE-hydrated Private IP: 172.31.18.46
```

The Pre-rehydrated ip addrress Future crashed message now is just printed to the console rather than logged to the logger, so the 
Pre-rehydrated ip address ("unknown") no longer appears in the logs, as shown above.


#### Synthetic thread futures crash code for testing

Given that the futures crash requires hyper-scaling, to minimize AWS testing costs, a synthetic crash was used to do a quick series of
unit tests on the re-hydration code. The code tested out very well.

Since the re-hydration is done at the process level, all of the aggreagate level stats and logs that are assembled from the 
process level registries (write-to-disk), self-corrected.

The code will be used for further testing with strategic placment of the crash from within install_tomcat function. Right now the testing
has the crash in between the SSH connection establishment and the for idx loop that iterates over the command execution set.

The synthetic crash code review will be in the code review section below.


The injection sites inside of install_tomcat are varied: 

From the .gitlab-ci.yml the sites can be changed very easily to expedite testing: 

```
deploy:
  stage: deploy
  variables:
    PID_JSON_DUMPS: "false"
    # this is a gating env VAR for module2 if I need to disable the process level resurrection candidate
    # or ghost json artifact files during hyper-scalling

    ##### Synthetic thread failures in install_tomcat ########
    FORCE_TOMCAT_FAIL: "false"  # ← Inject synthetic failure for testing (futures crash). The synthetic futures crash code is in instalL_tomcat. Use "1" or "true" to inject and "false" or "0" to not inject. This one is right before the for idx.

    FORCE_TOMCAT_FAIL_IDX1: "false"

    FORCE_TOMCAT_FAIL_POSTINSTALL: "false

    FORCE_TOMCAT_FAIL_PRE_SSH: "false""
```
Also added the ENV vars to the before script, importing them into the .env vile

```
before_script:
    - echo 'AWS_ACCESS_KEY_ID='${AWS_ACCESS_KEY_ID} >> .env
    - echo 'AWS_SECRET_ACCESS_KEY='${AWS_SECRET_ACCESS_KEY} >> .env
    - echo 'region_name=us-east-1' >> .env
    - echo 'image_id=ami-0f9de6e2d2f067fca' >> .env
    - echo 'instance_type=t2.micro' >> .env
    - echo 'key_name=generic_keypair_for_python_testing' >> .env
    - echo 'min_count=16' >> .env
    - echo 'max_count=16' >> .env
    - echo 'AWS_PEM_KEY='${AWS_PEM_KEY} >> .env
    - echo 'DB_USERNAME='${DB_USERNAME} >> .env
    - echo 'DB_PASSWORD='${DB_PASSWORD} >> .env
    - echo 'PID_JSON_DUMPS='${PID_JSON_DUMPS} >> .env  # see above. Gating for the json ghost and res candidate files.  
    - echo 'FORCE_TOMCAT_FAIL='${FORCE_TOMCAT_FAIL} >> .env # This is to inject a futures crash in install_tomcat
    - echo 'FORCE_TOMCAT_FAIL_IDX1='${FORCE_TOMCAT_FAIL_IDX1} >> .env # futures crash after first command executes
    - echo 'FORCE_TOMCAT_FAIL_POSTINSTALL='${FORCE_TOMCAT_FAIL_POSTINSTALL} >> .env  # futures crash after installation
    - echo 'FORCE_TOMCAT_FAIL_PRE_SSH='${FORCE_TOMCAT_FAIL_PRE_SSH} >> .env  # futures crash before SSH initiated
```


FORCE_TOMCAT_FAIL, the original injection site, is between the SSH connection code and the for idx command loop block (after SSH connection
is established, but before any commands are executed on the nodes through that SSH connection.

FORCE_TOMCAT_FAIL_IDX1 is designed to fire off AFTER the first command is executed (idx==0). When idx hits 1 the code causes the thread
to crash.

FORCE_TOMCAT_FAIL_POSTINSALL causes a thread crash after ALL of the commands have executed on the node (successfully), and right before
the install_success registry_entry is created

FORCE_TOMCAT_FAIL_PRE_SSH causes a thread crash before the SSH connection to the node is initiated.



The registry_entry will be tagged accordingly after RE-hydration:



```

    # Step 4: Rehydrate if safe
    if len(unknown_entries) == len(missing_ips_unhydrated):
        for thread_uuid, ip in zip(unknown_entries.keys(), missing_ips_unhydrated):
            process_registry[thread_uuid]["public_ip"] = ip
            process_registry[thread_uuid]["private_ip"] = public_to_private_ip.get(ip, "unknown")
            process_registry[thread_uuid]["tags"].append("ip_rehydrated")
            ####### tagging for syntehtic injections ########
            # Synthetic crash tagging
            if os.getenv("FORCE_TOMCAT_FAIL_PRE_SSH", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_pre_ssh")

            if os.getenv("FORCE_TOMCAT_FAIL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_between_ssh_and_commands")

            if os.getenv("FORCE_TOMCAT_FAIL_IDX1", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_idx_1")

            if os.getenv("FORCE_TOMCAT_FAIL_POSTINSTALL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_post_install")

```





#### Testing the simplified ghost detection logic with forced manual AWS console shutdown of instances

Early testing on this: The test revealed 3 SSH Exception install_failed threads and 2 futures crashes. The Futures crashes occurred
on instances that were stalled and not passing status checks. They were stopped and then started and encountered the futures crashes. 
This will be investigated further during Phase3 whereby the problematic thread(s) will initiate a stop and then start of the 
affected node(s).







#### resurrection_gateway function refactoring

The resurrection_gateway is the final decision maker in what can be resurrected and what cannot be resurrected. It uses input from the
3 blocks explained above in the resurrection_monitor.   It uses a combination of status, and the tags that are included in each 
registry_entry (thread) (which often have detailed technical information on the reason for the failure).  This sets the stage for the
Phase3 of this project whereby the threads will actually be resurrected and recovered and a fresh attempt at command set installation
will be attempted.





### Code Review of the fixes and refactoring:

#### resurrection_monitor_patch8 function changes

As noted above in the Implementation summary above, this function and some supporting functions requires several changes during the
refactoring. The original code was introduced prior to the registry_entry failure and stub logic being formalized, and so it was 
incorrect. Several portions of the deprecated code had to be removed (see the next section on that).
One important issue that surfaced while refactoring this code was that fact that a futures thread crash in install_tomcat caused the
ip addresses (Both public and private) go into an "unknown" state for obvoius reasons. This caused a lot of issues with the ghost
detection and resurrection_candidate detection logic, resulting in a double counting of the registry_entry in the missed ips (ghost) and
in the falure ips (install_failed status).   The solution to this was to RE-hydrate the registry_entry public and private ip(s) by 
determinstically pairing the thread_uuid of the thread with the so called "missing" ips (these IPs are obtained from the AWS golden list
of IPs from the orchestration level).  Althought this is not resurrection_monitor code, it is deeply integrated with it and the code review
will for this will be presented in a separate section furuther below.

This section reviews the code changes required to implement the design detailed earlier. namely the new ghost detection logic,
the untraceable registry code, and finally the resurrection candidate code. As noted above, an important part of this code is the logging
at a process level and aggregate level (all the processes in the execution) of these registry_entrys or ip(s).  A ghost log entry is
just an ip address whereas untraceable and resurrection candidate logs have full registry_entrys for forensic traceability. (see the 
earlier section for details on the logging)

NOTE: many of these blocks will be modularized into separate functions in the next major update.

Also note that these are all performed at the process level on the current process_registry. These are later aggregated in the main()
code from the aggregated registry.

The order of these blocks is important.


##### Ghost detection logic (BLOCK1)

```
    ###### BLOCK1: Ghost detection:
    ###### Refactoring the ghost detection logic. This will be modularized in a detect_ghosts() helper function at some point #######
    ###### The refactored code decouples the dependence on strictly ip address for the ghost detection. Now that the install_failed
    ###### and stub logic is much more robust and failure detection much more thorough, we need to pre-filter out several scenarios
    ###### that should not be ghosted even if the ip address is missing. For example a futures crash in a thread: the exception will
    ###### be caught and an install_failed registry_entry will be created. Often times there will be no ip address. There is now 
    ###### ip address recovery code in the tomcat_worker which RE-hydrates the ip address if it is unknown or blank.
    ###### This is required to be done prior to the ghost detection logic becasue ghost detection logic must be IP based.
    ###### The IP address is the only immuatable lasting attribute of a node and potential thread from AWS. 
    ###### If the ip address is missing in the registry_entry the untraceable entries in BLOCK2 will list these thread for further
    ###### review.  In theory these registry_entrys should not be included as ghosts because the thread_uuid is known and the failure
    ###### reason is usually included in the tags, but they do end  up in the missing (ghost) category as well.

    ##### Get rid of exluded_from_ghosting list (exclusion set). This does not work. Ghost detection is IP based.     ##### This IP based exclusion set has no purpose and will not
    ##### detect missing ips, it will merely identify registry_entrys without ip addresses. This is taken care of with BLOCK 2 logic.
    ##### This exclusion_set mehtodology can not be used to resolve the ghost detection issue with registry_entrys that have a missing
    ##### ip. These will be incorrectly listed as ghosts but the BLOCk 2 untraceable json file will alert the user with the information
    ##### for further investigatation on these types of threads.

    ## Step 1: Build exclusion set — IPs that should NOT be ghosted even if missing. This includes the edge cases described above 
    ## This uses the is_valid_ip helper function in case the ip addresses are malformed, etc.
    #excluded_from_ghosting = set()

    #for entry in process_registry.values():
    #    ip = entry.get("public_ip", "")
    #    status = entry.get("status", "")
    #    tags = entry.get("tags", [])

    #    if (
    #        "ip_unhydrated" in tags or
    #        (status in ["install_failed", "stub"] and (not ip or ip == "unknown" or not is_valid_ip(ip)))
    #    ):
    #        excluded_from_ghosting.add(ip)
    #        print(f"[RESMON_8] Skipping ghost detection for IP (exclusion set): {ip} — Reason: {status} + tag(s): {tags}")


    # Step 1: Build seen IPs normally
    seen_ips = {
        entry["public_ip"]
        for entry in process_registry.values()
        if entry.get("public_ip") and is_valid_ip(entry["public_ip"])
    }

    # Step 2: Build assigned IPs set from chunk
    assigned_ip_set = {ip["PublicIpAddress"] for ip in assigned_ips}

    # Step 3: Detect ghosts — assigned IPs not seen AND not excluded. This will prevent all the edge cases from getting ghosted.
    #ghosts = sorted(assigned_ip_set - seen_ips - excluded_from_ghosting)

    ## removed exclusion block:
    ghosts = sorted(assigned_ip_set - seen_ips)
    
    # Step 4: Log ghosts just as before the refactoring. These pid json files will be aggregated in main() for an aggregate json file.
    for ip in ghosts:
        print(f"[RESMON_8] 👻 Ghost detected in process {pid}: {ip}")

    if ghosts:
        ghost_file = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}_{ts}.json")
        with open(ghost_file, "w") as f:
            json.dump(ghosts, f, indent=2)
   
```




##### untraceable registry logic (BLOCK2)

These are regsitry_entrys that have a missing public/private ip. These have not been seen yet in actual testing but if they do occur, 
they will resemble a ghost and show up in the missing ips and ghost list and be detected by the ghost detection logic above. Thus, 
the purpose of this json log file (untraceable) is to notify the user that this thread needs further investigation beyond being a 
ghost.


```

    ##### BLOCK2: Untraceable registry_entrys:
    ##### As noted above these are usually install_failed or stub registry_entries with no ip address. This is a very rare occurrence yet
    ##### to be seen. A thread futures crash can cause this but we are able to rehydrate the ip addreses to these registry_entrys
    ##### Other cases may occur, but they have not been observed yet. In this case these install_failed and stub threads will unforunately
    ##### be missing ips and in the ghost category. This json file for untraceable registry entries will track these very special and rare
    ##### cases. Typically a real ghost will fail without a registry_entry or thread. This has been observed with ssh connection init issues
    ##### where there is no response from the node from the initial attempt to establish an SSH connection. Such cases will be true ghosts
    ##### and will not appear in this json file.
    ##### This is the process level json file. An aggregate file will be created as well in main() for the entire execution run.

    untraceable_entries = [
        entry for entry in process_registry.values()
        if not entry.get("public_ip") or not is_valid_ip(entry["public_ip"])
    ]

    if untraceable_entries:
        untraceable_file = os.path.join(log_dir, f"resurrection_untraceable_registry_entries_{pid}_{ts}.json")
        with open(untraceable_file, "w") as f:
            json.dump(untraceable_entries, f, indent=2)
```






##### resurrection candidate logic (BLOCK3)

Any registry_entry in the process_registry that is not install_success status needs to be categorized as a POTENTIAL resurrection 
candidate.The final determination on whether or not to reque the thread for resurrection will be made by the resurrection_gateway,
a separate process level function that will make the decision based upon the registry_entry tags and other information.

```
    ##### BLOCK3: Resurrection candidate code. The !=install_success status registry_entrys are included in this json as described
    ##### earlier in the comments above. This includes install_failed and stub registry_entrys

    # === RESMON_8 Resurrection Candidate Detection ===
    resurrection_candidates = []

    for thread_uuid, entry in process_registry.items():
        status = entry.get("status")
        if status and status != "install_success":
            resurrection_candidates.append(entry)
            print(f"[RESMON_8] Resurrection candidate detected: UUID {thread_uuid} | Status: {status}")

    # Generate timestamp for consistent artifact naming
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # Write artifact only if there are candidates
    if resurrection_candidates:
        candidate_file = os.path.join(log_dir, f"resurrection_candidates_pid_{pid}_{ts}.json")
        try:
            with open(candidate_file, "w") as f:
                json.dump(resurrection_candidates, f, indent=2)
            print(f"[RESMON_8] Resurrection candidate file written: {candidate_file}")
        except Exception as e:
            print(f"[RESMON_8] Failed to write resurrection candidate file: {e}")

    # Final verdict printout
    if resurrection_candidates:
        print(f"[RESMON_8] 🔍 Resurrection Candidate Monitor: {len(resurrection_candidates)} thread(s) flagged in process {pid}.")
    else:
        print(f"[RESMON_8] ✅ Resurrection Candidate Monitor: No thread failures in process {pid}.")

```


#### Cleanup of old code related to the resurrection_monitor code


There were several areas of legacy code that needed to be cleaned up. 

The code is commented out in the module if a systemactic  review is required.

1.Removal of BLOCK4 from install_tomcat. This code is no longer required and the logic is incorrect.

2.Removal of the resurrection_registry, resurrection_registry_lock and update_resurrection_registry. This registry was replace by the
process_registry.

3.Several other deprecated and faulty logic code blocks in resurrection_monitor_patch8. These were commented out and produced no collateral
effects.



#### RE-hydration code in tomcat_worker for the install_tomcat/threaded_install futures crash

The threaded_install function calls install_tomcat function for each thread through the ThreadPoolExecutor. A crash in the futures will
cause an exception. The exception will occur in install_tomcat and percolate up to threaded_install. The install_failed registry is
created in an except block to the ThreadPoolExecutor in threaded_install. 
The public and private ip address are lost in this this process ("unknown")

The registry_entry is created in this block of code in threaded_install:


```
                #### Add the debug except block for the traceback here: 
                except Exception as e:
                    import traceback
                    print(f"[ERROR][threaded_install] Future failed: {e}")
                    traceback.print_exc()

                    # Patch: Tag future failure in registry. The stub is for None, but if futures throws an error this will
                    # now catch it. This was found during a 512 hyper-scaling test.
                    pid = multiprocessing.current_process().pid
                    failed_uuid = uuid.uuid4().hex[:8]
                    failed_entry = {
                        "status": "install_failed",
                        "attempt": -1,
                        "pid": pid,
                        "thread_id": threading.get_ident(),
                        "thread_uuid": failed_uuid,
                        #"public_ip": ip if 'ip' in locals() else "unknown",
                        #"private_ip": private_ip if 'private_ip' in locals() else "unknown",
                        "public_ip": "unknown",
                        "private_ip": "unknown",
                        "timestamp": str(datetime.utcnow()),
                        "tags": ["install_failed", "future_exception", type(e).__name__],
                        #"tags": ["install_failed", "future_exception", "ip_unhydrated", type(e).__name__]
                    }

                    ##### create the registry_entry and print the log  
                    thread_registry[failed_uuid] = failed_entry # create the registry_entry
                   

                    ##### We no longer want to send the pre-rehydrated unknown address field to the logs. The benchmark pid log files
                    ##### get this "unknown" and it corrupts the benchmark combined runtime log and then the benchmark_ips_artifact.log
                    ##### Instead just print the Pre-rehydrated unknown and do the logging.info in tomcat_worker during the batch
                    ##### rehydration for loop

                    #logging.info(f"[PID {pid}] [UUID {failed_uuid}] ❌ Future crashed | Public IP: {failed_entry['public_ip']} | Private IP: {failed_entry['private_ip']}")


                    print(f"[PID {pid}] [UUID {failed_uuid}] ❌ Future crashed | Pre-rehydrated Public IP: {failed_entry['public_ip']} | Pre-rehydrated Private IP: {failed_entry['private_ip']}")

 
                    ###### the unknown ip addresses in the crash thread case above will need to be rehydrated. This will be done in 
                    ###### the tomcat_worker function (the calling function to this threaded_install function) right after
                    ###### threaded_install returns the process_registry for this process. It is best to batch process the 
                    ###### ip rehydration to avoid ip mis-assiginment.
```



This unknown ip address needs to be RE-hydrated mainly because an "unknown" ip address in the ip based logs makes the 
ghost detection and resurrection logic incorrectly assess status.

The RE-hydration has to be done in tomcat_worker which is the calling function to threaded_install. The reason for this is 
because the RE-hydration has to be done using the missing ip list of the process, and this is not known until the process is done
completing processing all of the threads in the process. This is in tomcat_worker.

Note that the logging.info logs to the logger which is configured to log to log_path = f'/aws_EC2/logs/benchmark_{pid}_{unique_id}.log'
The logger is defined in tomcat_worker_wrapper and is inherited to tomcat_worker and then to this threaded_install.

This also has to be fixed. If an "unknown" is logged to the benchmark pid log file, it will "corrupt" that process level log file.
These process level logs are aggregated into the benchamrk_combined_runtime.log and bechmark_combined.log and the 
benchmark_ips_artfiact.log collects the ip addresses from the benchmark_combined_runtime.log into a log file. 
With "unknown" in the process level files, these ips will be completely lost and show up blank in the benchmark_ips_artifact.log file.

The best way to fix this is to incorporate the logging.info message into the for loop of the RE-hydration code as shown below. This 
RE-hydration code, as mentioned above, is in tomcat_worker. This permits a batch processing on the ip RE-hydration and also makes it 
easy to log that Future crashed message to the logger using the RE-hydrated ip addreses of each thread in the process.
Resolving this issue at the process level will self correct all the other upper level logs like the aggregate benchmark logs and the
benchmark ips list log that is extracted from the aggregate. 

The RE-hydration code is in the tomcat_worker:


```
    ####### [tomcat_worker]
    ####### Rehydration of the unknown ips in thread futures crash cases is absolutely necessary to preserve
    ####### the integrity of the upstream logging. Otherwise a "unknown" will appear in the total ips and failure
    ####### ips logs and futhermore the upstream ghost detection logic will not work with unknown in ip based
    ####### variable lists.   

    ####### The approach is: For a given process determine which registry_entrys have unknown in the ip fields
    ####### This is called unknown_entries
    ####### Once this is determined, compute the seen_ips_unhydrated, i.e. the seen ip addresses in the proces_registry
    ####### for this process. Then determie the delta between this list and the assigned ips to this chunk (the golden
    ####### list of ip addresses designated for this process to work on).  
    ####### This gives a missing ip list prior to 
    ####### rehydration (missing_ips_unhydrated).   This is the list of ips that will be used to rehydrate the 
    ####### registry_entrys that have the unknown ips in them.   This uses a zip function so for example:
    ####### thread_uuid 1 will get ip1 in the missing list, thread_uuid 2 will get ip2 in the missing list, and so on.
    ####### thread_uuid 1 and 2 have already been identified as those registry_entrys in this process with unknown ips

    ####### Prior to rehydration there needs to be a check to ensure that the NUMBER (len) of missing unhydrate ips 
    ####### is exactly the same as the NUMBER (len) of unknown_entries (registry_entrys with unknown ips).  
    ####### This is to guard against the very very unlikely case that there is a true ghost ip (completely unassigned
    ####### to a thread, but present in the golden list) and these unknown threads.  If these two numbers are not the
    ####### same then that means that there are true ghosts in the missing unhydrate ips and the code cannot 
    ####### deterministically assign ip addreses to the regsitry_entrys with unknown ip addresses. In this case
    ####### the registry_entrys will be tagged as ip_unhydrated and the "unknown" will appear in the logs, etc.
    ####### This will be indicative that there are several ips that are unaccounted for (ghosts and some that are
    ####### from thread crashes). Right now there is no way to deal with this highly unlikely scenario.

    ######## Note that if there is a ghost in process 1 and an unknown in process 2 (two separate processes), this 
    ######## case can be handles with the ghost being desiginated as missing ips in the logs and the unknown
    ######## registry_entrys being rehydrated with the failed thread original ip address(es).

    ######## Note2: the reason why this is so challenging ig because _args are not avaliable from the thread that
    ######## crashes. This was attempted originally and results in a NameError in the python code. The instance id, 
    ######## and all the other attribues of the thread are lost when it crashes.  Initially tried using _args[2] to
    ######## get the instance id of the crashed thread but this did not work due to this reason.

    ######## Note3: It is best to do this rehydration as batch processing on the entire processs registry_entrys instead
    ######## of doing it inside threaded_install exception block for ThreadPoolExector. This is because of the way that the 
    ######## ip addresses are rehydrated. See comments above for the detail on how this is done.
    #- Guarantees one-to-one mapping between missing IPs and unknown UUIDs  
    #- Avoids race conditions and duplicate assignments  
    #- Preserves semantic clarity and forensic traceability  
    #- Keeps logs clean and upstream  ghost detection logic in the resurrection monitor (further below) deterministic


    # ------------------ [tomcat_worker] RESMON_8 PATCH: Batch Rehydration ------------------
    assigned_ip_set = {ip["PublicIpAddress"] for ip in instance_info} # note that instance_info is the same thing as assigned_ips that is used in resurrection_monitor_patch8. Assigned ips are the ips in the chunk list of ips that the process is working with.(golden list of ips)


    # Build a mapping from public IP → private IP for full rehydration. This is so that we can rehydrate the private ip field as well.
    public_to_private_ip = {
        ip["PublicIpAddress"]: ip["PrivateIpAddress"]
        for ip in instance_info
    }

    # Step 1: Identify registry entries with unknown public IPs
    unknown_entries = {
        thread_uuid: entry for thread_uuid, entry in process_registry.items()
        if entry.get("public_ip") == "unknown"
    }

    # Step 2: Compute seen IPs before rehydration
    seen_ips_unhydrated = {
        entry["public_ip"]
        for entry in process_registry.values()
        if is_valid_ip(entry.get("public_ip"))
    }

    # Step 3: Compute missing IPs before rehydration
    missing_ips_unhydrated = sorted(list(assigned_ip_set - seen_ips_unhydrated))

    # Step 4: Rehydrate if safe
    if len(unknown_entries) == len(missing_ips_unhydrated):
        for thread_uuid, ip in zip(unknown_entries.keys(), missing_ips_unhydrated):
            process_registry[thread_uuid]["public_ip"] = ip
            process_registry[thread_uuid]["private_ip"] = public_to_private_ip.get(ip, "unknown")
            process_registry[thread_uuid]["tags"].append("ip_rehydrated")
            ####### tagging for syntehtic injections ########

            # Synthetic crash tagging
            if os.getenv("FORCE_TOMCAT_FAIL_PRE_SSH", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_pre_ssh")

            if os.getenv("FORCE_TOMCAT_FAIL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_between_ssh_and_commands")

            if os.getenv("FORCE_TOMCAT_FAIL_IDX1", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_idx_1")

            if os.getenv("FORCE_TOMCAT_FAIL_POSTINSTALL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_post_install")
                process_registry[thread_uuid]["tags"].append("install_success_achieved_before_crash")
                
                #the crash is positioned so that all commands are executed successfully. The crash will not be hit otherwise. 
                # It is basically an install_success but with a crash right before registry creation.



            ##### insert the logging.info here to resolve the issue whereby the benchmark pid log file is getting "unknown" 
            ##### Pre-rehydrated ip addresses when the futures thread crashes in threaded_install. Just do a print in threaded_install
            ##### Do the logging here in tomcat worker for each thread in the rehydration batch processing that has an unknown.
            ##### This way the benchmark pid log file will not be corrupted with unknowns and will have rehydrated ip addresses and
            ##### benchmark combined runtime log will have rehydrated ips and finally benchmark_ips_artifact.log will have ip addresses
            # RESMON PATCH: Log rehydrated IPs to benchmark PID log and console

            logging.info(f"[PID {pid}] [UUID {thread_uuid}] ❌ Future crashed | RE-hydrated Public IP: {process_registry[thread_uuid]['public_ip']} | RE-hydrated Private IP: {process_registry[thread_uuid]['private_ip']}")
            
            print(f"[PID {pid}] [UUID {thread_uuid}] ❌ Future crashed | RE-hydrated Public IP: {process_registry[thread_uuid]['public_ip']} | RE-hydrated Private IP: {process_registry[thread_uuid]['private_ip']}")

            print(f"[tomcat_worker RESMON_8_PATCH] Rehydrated IP {ip} for UUID {thread_uuid}")

    else:
        logging.warning(f"[tomcat_worker RESMON_8_PATCH] Rehydration skipped for PID {pid}: ghost(missing ip) + unknown ip detected — cannot resolve IP ambiguity")
        for thread_uuid in unknown_entries:
            process_registry[thread_uuid]["tags"].append("ip_unhydrated")

```







#### Synthetic thread futures crash injection


The code snippets of the code blocks are below. All of these crashes are strategically placed inside of the install_tomcat function.
The particular crash is a thread futures crash.  The regression testing with these in place went very well.


##### FORCE_TOMCAT_FAIL

```
        <<< SSH Connection has been established for the thread/node >>>>

        ##### This code below is a synthetic crash injection to test the futures thread crash code that has been added in the 
        ##### resurrection_monitor_patch8.  The ghost detection logic and resurrection candidate logic is in that function.
        ##### prior to the fix, the ghost detection logic was too aggressive, marking instalL_failed registry_entry as ghost.
        #### Thus as an install_failed registry_entry it was double counted as failed ip and a ghost ip.  It is not a ghost ip.
        #### The reason for this is because a futures thread crash will cause the thread ip to go into an unknown state.  As an 
        #### ip "unknown" the ghost detection logic kicks in and counts it as a missing ip address, which is a ghost.
        #### However, these types of thread failures are NOT ghosts. They have a thread_uuid and a registry_entry and their cause
        #### of failure is known (thread futures crash).  The solution to this problem is to RE-hydrate the ip address from the 
        #### so called "missing" ip(s) at a per process level. The missing ip(s) can easily be detected from a delta between the 
        #### AWS golden list of ips (orchestration level ip address list) and the ips that are currently assigned to registry_entrys
        #### for that process.  To test this, typically it is required to run a hyper-scaling test (512 node test is ideal). However,
        #### to save on costs of running such tests, crash simulation code permits a full testing of the RE-hydration code for 
        #### futhres thread crashes without have to run repeated hyper-scale tests.

        #### The crash simulation code below will incite a futures thread crash in install_tomcat that
        #### will percolate up to the calling function threaded_install (ThreadPoolExecutor invokes install_tomcat from there).
        #### This causes the except block in threaded_install to trigger and creates a registry_entry wih an unknown ip and install_failed
        #### with the tags indicating that it is a futures crash. The flag FORCE_TOMCAT_FAIL is set in .gitlab-ci.yml file and imported
        #### as in env variable. It will force all the processes/threads in the execution run to fail. There will be no install_success
        #### on any of the threads. This type of crash will cause the batch RE-hydration code in tomcat_worker (the calling function of
        #### threaded_install) to execute and all of the code paths can thus be executed. These crashes have been strategically placed
        #### throughout the install_tomcat function to ensure that the exception code handling and RE-hydration code are robust under
        #### various thread failure points in install_tomcat. This one is placed in between the SSH code connect and the for idx 
        #### command execution block. The others are placed pre-SSH, post-install, and after the first command executes (idx==1)
        if os.getenv("FORCE_TOMCAT_FAIL", "false").lower() in ("1", "true"):
            raise RuntimeError("Synthetic failure injected between SSH and install loop")




        #### this introduces the wrap command that will look for bash and bash-like commands and wrap them in the strace transform
        #### The helper functions wrap_command and should_wrap and the native_commands list that is from the original commands list
        #### are at the top of this module but later on will modularize the wrap command so that it can be used with other 
        #### service installations like gitlab and mariadb, etc....

        commands = [wrap_command(cmd) for cmd in native_commands]



        #### Beigin the for idx loop which contains the for attempt loop which does the command list iteration
        #NON-Negative testing use this: (and comment out the above)
        for idx, command in enumerate(commands):
```
This is the registry_entry of a sample thread for this crash: 

```
"d8e8373e": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 16,
    "thread_id": 129715465186176,
    "thread_uuid": "d8e8373e",
    "public_ip": "3.80.85.194",
    "private_ip": "172.31.26.119",
    "timestamp": "2025-10-18 04:20:02.394657",
    "tags": [
      "install_failed",
      "future_exception",
      "RuntimeError",
      "ip_rehydrated",
      "synthetic_crash_between_ssh_and_commands"
    ]
  },
```

##### FORCE_TOMCAT_FAIL_IDX1

```
        #### Beigin the for idx loop which contains the for attempt loop which does the command list iteration
        #NON-Negative testing use this: (and comment out the above)
        for idx, command in enumerate(commands):

            ## Negative testing:
            #if ip == target_ip and idx == 1:
            #    command = 'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat99'



        ## the commands are listed at the top of tomcat_worker(), the calling function. There are 4 of them. These can
        ## be modified for any command installation type (any application)

            ##### Synthetic thread futures crash injection at beginning of for idx loop
            print(f"[DEBUG] idx={idx}, FORCE_TOMCAT_FAIL_IDX1={os.getenv('FORCE_TOMCAT_FAIL_IDX1')}")



            if os.getenv("FORCE_TOMCAT_FAIL_IDX1", "false").lower() in ("1", "true") and idx == 1:
                raise RuntimeError("Synthetic failure injected at idx 1")

```

These are the gitlab console logs for this crash:

Note that the command 2/5 never starts becasue the crash code is positioned right at the beginning of the for idx loop. 
Note also that the command 1/5 successfully completes.
Finally, note that the registry_entry is successfully RE-hydrated as expected.




```
[DEBUG] idx=0, FORCE_TOMCAT_FAIL_IDX1=1
[18.212.222.90] [2025-10-19 23:47:42.659291] Command 1/5: sudo DEBIAN_FRONTEND=noninteractive apt update -y (Attempt 1)

<< Command 2/5 loop starts but the command is never executed because the crash is positioned at the top of the for idx loop >>

[DEBUG] idx=1, FORCE_TOMCAT_FAIL_IDX1=1
[ERROR][threaded_install] Future failed: Synthetic failure injected at idx 1
Traceback (most recent call last):
  File "<string>", line 5676, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 4411, in install_tomcat
RuntimeError: Synthetic failure injected at idx 1
[PID 12] [UUID 9ad83042] ❌ Future crashed | Pre-rehydrated Public IP: unknown | Pre-rehydrated Private IP: unknown

<<Note the thread is subsequently rehydrated just fine. See the regsitry_entry sample below>>
 
[PID 12] [UUID 9ad83042] ❌ Future crashed | RE-hydrated Public IP: 54.172.218.112 | RE-hydrated Private IP: 172.31.20.231
[RESMON_8_PATCH] Rehydrated IP 54.172.218.112 for UUID 9ad83042
```



This is a sample registry_entry from the gitlab artifact logs:

```
  "a5abdc1b": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 17,
    "thread_id": 130184963406720,
    "thread_uuid": "a5abdc1b",
    "public_ip": "18.212.222.90",
    "private_ip": "172.31.16.158",
    "timestamp": "2025-10-19 23:48:19.987157",
    "tags": [
      "install_failed",
      "future_exception",
      "RuntimeError",
      "ip_rehydrated",
      "synthetic_crash_idx_1"
    ]
  },

```

##### FORCE_TOMCAT_FAIL_POSTINSALL


```

        # END of the for idx loop
        # outer for idx loop ends and close the ssh connection if it has successfuly completed all commands execution

        ssh.close()
        transport = ssh.get_transport()
        if transport:
            transport.close()



        # Synthetic crash after install loop but before registry commit
        if os.getenv("FORCE_TOMCAT_FAIL_POSTINSTALL", "false").lower() in ("1", "true"):
            raise RuntimeError("Synthetic failure injected after install loop")


        #debug for patch7c
        print(f"[TRACE][install_tomcat] Reached successful registry update step for {ip}")
```

If the code executes this crash, the for idx loop has completed its iteration through all of the commands and it is safe to assume
that the installation is succesful (the install_success registy_entry is create shortly after this).  Thus the tags will reflect this.
The tags can then be used retroactively by the resurrection_gatekeeper to decide: 

- Skip requeueing these nodes entirely (Do not attempt to resurrect the threads)
- Requeue them for sanity checks or post-install audits
- Flag them for deeper forensic review if other anomalies are present


The tags indicate that the installation is successful but the thread crashed. The resurrection_gatekeeper will use tags for one of its
filtering criteria on whether or not to reque the thread for resurrection.

The tagging is ideally done in the RE-hydration block of code in tomcat_worker as shown below. The logic is straightforward: 
If and only if a  post install crash has been incited, then tag it with the last tag below:



```
    # Step 4: Rehydrate if safe
    if len(unknown_entries) == len(missing_ips_unhydrated):
        for thread_uuid, ip in zip(unknown_entries.keys(), missing_ips_unhydrated):
            process_registry[thread_uuid]["public_ip"] = ip
            process_registry[thread_uuid]["private_ip"] = public_to_private_ip.get(ip, "unknown")
            process_registry[thread_uuid]["tags"].append("ip_rehydrated")
            ####### tagging for syntehtic injections ########
            # Synthetic crash tagging
            if os.getenv("FORCE_TOMCAT_FAIL_PRE_SSH", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_pre_ssh")

            if os.getenv("FORCE_TOMCAT_FAIL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_between_ssh_and_commands")

            if os.getenv("FORCE_TOMCAT_FAIL_IDX1", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_idx_1")

            if os.getenv("FORCE_TOMCAT_FAIL_POSTINSTALL", "false").lower() in ("1", "true"):
                process_registry[thread_uuid]["tags"].append("synthetic_crash_post_install")
                process_registry[thread_uuid]["tags"].append("install_success_achieved_before_crash")
                #the crash is positioned so that all commands are executed successfully. The crash will not be hit otherwise. It is basically an install_success but with a crash right before registry creation.

```


These are the gitlab console logs for this crash. Note that the command 5/5 is the last command to be executed on eacy node: 


```
[54.242.123.31] [2025-10-20 03:02:16.796035] Command 5/5: sudo systemctl enable tomcat9 (Attempt 1)
[54.242.123.31] Reset command before mutation AND set to original_command: sudo systemctl enable tomcat9
[54.242.123.31]  Wrapped processed command(strace debug): sudo systemctl enable tomcat9
[TRACE1][54.242.123.31] [2025-10-20 03:02:16.796065] Command 5/5: sudo systemctl enable tomcat9 (Attempt 1) — About to invoke exec_command
[TRACE][install_tomcat] Attempt loop exited for command 5/5: 'sudo systemctl enable tomcat9' on IP 54.226.208.72 — Success flag: True
[ERROR][threaded_install] Future failed: Synthetic failure injected after install loop
Traceback (most recent call last):
  File "<string>", line 5688, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 5400, in install_tomcat
RuntimeError: Synthetic failure injected after install loop
[PID 13] [UUID 702b7be8] ❌ Future crashed | Pre-rehydrated Public IP: unknown | Pre-rehydrated Private IP: unknown

<< Note that the thread is subsequently rehydrated just fine >>

[PID 13] [UUID 702b7be8] ❌ Future crashed | RE-hydrated Public IP: 18.234.214.3 | RE-hydrated Private IP: 172.31.24.54

```
This is a sample registry_entry from this:
Note the tag install_success_acheived_before_crash. This will help the resurrection_gatekeeper in terms of reque the thread or not.
The AWS instances were verified manually and in this case do actaully have a working version of the application running, so thhe
tag is appropriate.

```
 "702b7be8": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 13,
    "thread_id": 132130459024256,
    "thread_uuid": "702b7be8",
    "public_ip": "18.234.214.3",
    "private_ip": "172.31.24.54",
    "timestamp": "2025-10-20 03:02:18.598648",
    "tags": [
      "install_failed",
      "future_exception",
      "RuntimeError",
      "ip_rehydrated",
      "synthetic_crash_post_install",
      "install_success_achieved_before_crash"
    ]
  },

```


##### FORCE_TOMCAT_FAIL_PRE_SSH

```

        ssh_connected = False
        status_tagged = False
        registry_entry_created = False
        ssh_success = False  # temp flag to suppress stub




        # Synthetic crash before SSH connect loop
        if os.getenv("FORCE_TOMCAT_FAIL_PRE_SSH", "false").lower() in ("1", "true"):
            raise RuntimeError("Synthetic failure injected before SSH connect loop")



        for attempt in range(5):
            try:
                print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")

```




```
[TRACE][install_tomcat] Beginning installation on 54.172.110.32
[ERROR][threaded_install] Future failed: Synthetic failure injected before SSH connect loop
[PID 14] [UUID afe32e77] ❌ Future crashed | Pre-rehydrated Public IP: unknown | Pre-rehydrated Private IP: unknown
Traceback (most recent call last):
  File "<string>", line 5688, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 3906, in install_tomcat
RuntimeError: Synthetic failure injected before SSH connect loop

[RESMON_7d] Raw line 49: '2025-10-20 04:10:10,766 - 14 - MainThread - [PID 14] [UUID afe32e77] ❌ Future crashed | RE-hydrated Public IP: 34.229.144.156 | RE-hydrated Private IP: 172.31.19.60\n'
[RESMON_7d] Matched IPs: ['34.229.144.156', '172.31.19.60']

```

```
 "afe32e77": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 14,
    "thread_id": 132040951040896,
    "thread_uuid": "afe32e77",
    "public_ip": "34.229.144.156",
    "private_ip": "172.31.19.60",
    "timestamp": "2025-10-20 04:10:09.762610",
    "tags": [
      "install_failed",
      "future_exception",
      "RuntimeError",
      "ip_rehydrated",
      "synthetic_crash_pre_ssh"
    ]
  },
```


### Hyperscaling processes test at 512, provoked ghost detection logic


Following an AWS outage on 10/20/25, the hyperscaling test on 10/21 had one execution run that exhibited residual effects of the 
issue AWS had with their network load monitoring system.

The test exhibited the following which is consistent with a residual load based issue that they addressed:

- Instances launched but not fully hydrated
- No metadata service response
- No SSH banner
- No registry entry, no PID, no thread UUID — just silence

This was a very transient issue. 

The 512 node test that followed this test (an hour later) was 100% successful which is the normal case when the 
VPS controller running the python processes is NOT under swap contentiion. thrashing or presssure. (~ 30GB of the 36GB of swap was
in use).

The logs were extremely interesting in the crash/ghost case; a very consistent and robust accounting of what happened:

There were 512 EC2 nodes that were brought up successfully. Of the 512, 14 were completely lost with no other logs other than the 
the sample shown below: 


```
TRACE][aggregator] Aggregate GOLD IPs from chunk hydration:
  100.24.47.94 
  100.25.216.2 <<<< this is one of the 14 ghosts
(output truncated as there are a total of 512 ip addresses)
```

And this, below: 

(note this process number is just an index and not the actual PID. So the python multiprocessing.Pool did designate this chunk
of 1 ip address, this missing ip address, to one of the 512 processes but it never actually resulted in an registry_entry because there
are no further logs for this ip address. All 14 ghosts had this same signature indicating that there was a common cause (namely an
after effect of the AWS outage when put under load)

```
[DEBUG] Process 190: chunk size = 1
[DEBUG] Process 190: IPs = ['100.25.216.2']
```

The aggregate logs from main() give an overall picture of the full context of what happened here: 
Note that there is no accounting for the missing ips in the "Final registry summary" below because by definition missing ips are ghosts
and do not have an associated registry_entry (no thread_uuid, pid, status, etc....)



The root cause — an AWS failure in their **network load monitoring system** — explains this composite picture below of missing ips and 
install_failed with variants of thread futures crashes.



```
[TRACE][aggregator] Final registry summary:
  total: 498
  install_success: 492
  gatekeeper_resurrect: 0
  watchdog_timeout: 0
  ssh_initiated_failed: 0
  ssh_retry_failed: 0
  install_failed: 6
  stub: 0
  no_tags: 0
[TRACE][aggregator] Wrote 498 IPs to /aws_EC2/logs/total_registry_ips_artifact.log
[TRACE][aggregator] Wrote 492 IPs to /aws_EC2/logs/successful_registry_ips_artifact.log
[TRACE][aggregator] Wrote 6 IPs to /aws_EC2/logs/failed_registry_ips_artifact.log
[TRACE][aggregator] Wrote 14 IPs to /aws_EC2/logs/missing_registry_ips_artifact.log
[TRACE][aggregator] Wrote 6 candidates to /aws_EC2/logs/resurrection_candidates_registry_1761086930.json
[TRACE][aggregator] Wrote 14 ghosts to /aws_EC2/logs/resurrection_ghost_missing_1761086930.json
[TRACE][aggregator] Wrote 14 ghosts to /aws_EC2/logs/aggregate_ghost_summary.log
[TRACE][aggregator] Wrote 0 untraceable entries to /aws_EC2/logs/resurrection_untraceable_registry_entries_1761086930.json
```

There were 512 total nodes brought up during the AWS orchestration phase.   The benchmark logs which record the CPU and stats as well
as the installation success or failure status of the node (thread), have no entires or logs for the 14 missing ghosts.

The code that was exercised here was teh BLOCK1 ghost detection logic: 

The assigned_ips is directly from the chunk data from the golden ip list that is created during AWS orchestration. (all 512 addresses)

The seen_ips is the ip addreses for which registry_entry is created (i.e. a thread_uuid is designed for the thread to record the 
installation success or failure of the node.


The delta between these two consitutes a missing ip list (missing_registry_ips_artifact.log), which is a listing of all the ips in 
the execution run that are missing (no thread_uuid, etc.). Sometimes these ghost are created when the SSH init gets absolutely no
response from the node, but in this case there was nothing in the logs. (very rare and never seen before)

```
    # Step 1: Build seen IPs normally
    seen_ips = {
        entry["public_ip"]
        for entry in process_registry.values()
        if entry.get("public_ip") and is_valid_ip(entry["public_ip"])
    }

    # Step 2: Build assigned IPs set from chunk
    assigned_ip_set = {ip["PublicIpAddress"] for ip in assigned_ips}

    # Step 3: Detect ghosts — assigned IPs not seen AND not excluded. This will prevent all the edge cases from getting ghosted.
    #ghosts = sorted(assigned_ip_set - seen_ips - excluded_from_ghosting)

    ## removed exclusion block:
    ghosts = sorted(assigned_ip_set - seen_ips)

    # Step 4: Log ghosts just as before the refactoring. These pid json files will be aggregated in main() for an aggregate json file.
    for ip in ghosts:
        print(f"[RESMON_8] 👻 Ghost detected in process {pid}: {ip}")

    if ghosts:
        ghost_file = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}_{ts}.json")
        with open(ghost_file, "w") as f:
            json.dump(ghosts, f, indent=2)
```

In addition to these 14 ghosts there were 6 install_failed reigistry_entrys indicating that there was other instability in the 
AWS network. The install_failed on these 6 threads consisted of a few different types of failuers as indicated below in their
registry_entrys. There were all future_exceptions in the ThreadPoolExecutor (threaded_install and install_tomcat), and were all 
successfully RE-hydrated by the new code.

```
"748cc5cd": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 116,
    "thread_id": 125484197100416,
    "thread_uuid": "748cc5cd",
    "public_ip": "54.90.184.111",
    "private_ip": "172.31.28.48",
    "timestamp": "2025-10-21 22:22:41.199461",
    "tags": [
      "install_failed",
      "future_exception",
      "SSHException",
      "ip_rehydrated"
    ]
  },


 "b965bb3c": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 45,
    "thread_id": 125484197100416,
    "thread_uuid": "b965bb3c",
    "public_ip": "52.200.231.194",
    "private_ip": "172.31.31.200",
    "timestamp": "2025-10-21 22:22:52.155186",
    "tags": [
      "install_failed",
      "future_exception",
      "SSHException",
      "ip_rehydrated"
    ]
  },

 "fc12286b": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 281,
    "thread_id": 125484197100416,
    "thread_uuid": "fc12286b",
    "public_ip": "3.80.24.212",
    "private_ip": "172.31.30.13",
    "timestamp": "2025-10-21 22:22:34.112081",
    "tags": [
      "install_failed",
      "future_exception",
      "SSHException",
      "ip_rehydrated"
    ]
  },

 "89e89ea6": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 215,
    "thread_id": 125484197100416,
    "thread_uuid": "89e89ea6",
    "public_ip": "98.93.226.18",
    "private_ip": "172.31.17.108",
    "timestamp": "2025-10-21 22:22:40.563036",
    "tags": [
      "install_failed",
      "future_exception",
      "SSHException",
      "ip_rehydrated"
    ]
  },

 "4b3d67a7": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 115,
    "thread_id": 125484197100416,
    "thread_uuid": "4b3d67a7",
    "public_ip": "52.71.254.145",
    "private_ip": "172.31.20.56",
    "timestamp": "2025-10-21 22:22:51.306199",
    "tags": [
      "install_failed",
      "future_exception",
      "UnboundLocalError",
      "ip_rehydrated"
    ]
  },


 "1ec935e1": {
    "status": "install_failed",
    "attempt": -1,
    "pid": 148,
    "thread_id": 125484197100416,
    "thread_uuid": "1ec935e1",
    "public_ip": "44.223.23.125",
    "private_ip": "172.31.20.238",
    "timestamp": "2025-10-21 22:22:40.341129",
    "tags": [
      "install_failed",
      "future_exception",
      "SSHException",
      "ip_rehydrated"
    ]
  },

```

There were basically 3 types of future crashes: Error reading SSH protocol banner, encountered RSA key, expected OPENSSH key, and Failed to establish a new connection: [Errno -3] Temporary failure in name resolution (UnboundLocalError in the registry_entry above).

```

[ERROR][threaded_install] Future failed: Error reading SSH protocol banner
Get:2 http://us-east-1.ec2.archivTraceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 2369, in _check_banner
    buf = self.packetizer.readline(timeout)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/packet.py", line 395, in readline
    buf += self._read_timeout(timeout)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/packet.py", line 673, in _read_timeout
    raise socket.timeout()
TimeoutError

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<string>", line 5691, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 3990, in install_tomcat
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 451, in connect
    t.start_client(timeout=timeout)
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 773, in start_client
    raise e
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 2185, in run
    self._check_banner()
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 2373, in _check_banner
    raise SSHException(
paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
e.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]

```







```
[ERROR][threaded_install] Future failed: encountered RSA key, expected OPENSSH key
Traceback (most recent call last):
  File "<string>", line 5691, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 5322, in install_tomcat
UnboundLocalError: cannot access local variable 'stdin' where it is not associated with a value
  File "<string>", line 5691, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 3990, in install_tomcat
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 485, in connect
    self._auth(
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 818, in _auth
    raise saved_exception
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 730, in _auth
    key = self._key_from_filepath(
          ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 638, in _key_from_filepath
    key = klass.from_private_key_file(key_path, password)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/pkey.py", line 435, in from_private_key_file
    key = cls(filename=filename, password=password)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/ed25519key.py", line 60, in __init__
    pkformat, data = self._read_private_key("OPENSSH", f)
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/pkey.py", line 543, in _read_private_key
    raise SSHException(
paramiko.ssh_exception.SSHException: encountered RSA key, expected OPENSSH key

```



```
multiprocessing.pool.RemoteTraceback: 
"""
Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/urllib3/connection.py", line 174, in _new_conn
    conn = connection.create_connection(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/util/connection.py", line 72, in create_connection
    for res in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/socket.py", line 962, in getaddrinfo
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
socket.gaierror: [Errno -3] Temporary failure in name resolution

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/botocore/httpsession.py", line 464, in send
    urllib_response = conn.urlopen(
                      ^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    retries = retries.increment(
              ^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/util/retry.py", line 525, in increment
    raise six.reraise(type(error), error, _stacktrace)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/packages/six.py", line 770, in reraise
    raise value
  File "/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 703, in urlopen
    httplib_response = self._make_request(
                       ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 386, in _make_request
    self._validate_conn(conn)
  File "/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 1042, in _validate_conn
    conn.connect()
  File "/usr/local/lib/python3.11/site-packages/urllib3/connection.py", line 358, in connect
    self.sock = conn = self._new_conn()
                       ^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/urllib3/connection.py", line 186, in _new_conn
    raise NewConnectionError(
urllib3.exceptions.NewConnectionError: <botocore.awsrequest.AWSHTTPSConnection object at 0x72208ba19b50>: Failed to establish a new connection: [Errno -3] Temporary failure in name resolution

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 125, in worker
    result = (True, func(*args, **kwds))
                    ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 51, in starmapstar
    return list(itertools.starmap(args[0], args[1]))
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 1100, in tomcat_worker_wrapper
  File "<string>", line 3723, in tomcat_worker
  File "<string>", line 923, in retry_with_backoff
  File "/usr/local/lib/python3.11/site-packages/botocore/client.py", line 570, in _api_call
    return self._make_api_call(operation_name, kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/context.py", line 124, in wrapper
    return func(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/client.py", line 1013, in _make_api_call
    http, parsed_response = self._make_request(
                            ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/client.py", line 1037, in _make_request
    return self._endpoint.make_request(operation_model, request_dict)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 119, in make_request
    return self._send_request(request_dict, operation_model)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 200, in _send_request
    while self._needs_retry(
          ^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 360, in _needs_retry
    responses = self._event_emitter.emit(
                ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/hooks.py", line 412, in emit
    return self._emitter.emit(aliased_event_name, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/hooks.py", line 256, in emit
    return self._emit(event_name, kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/hooks.py", line 239, in _emit
    response = handler(**kwargs)
               ^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 207, in __call__
    if self._checker(**checker_kwargs):
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 284, in __call__
    should_retry = self._should_retry(
                   ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 320, in _should_retry
    return self._checker(attempt_number, response, caught_exception)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 363, in __call__
    checker_response = checker(
                       ^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 247, in __call__
    return self._check_caught_exception(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/retryhandler.py", line 416, in _check_caught_exception
    raise caught_exception
  File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 279, in _do_get_response
    http_response = self._send(request)
                    ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py", line 383, in _send
    return self.http_session.send(request)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/botocore/httpsession.py", line 493, in send
    raise EndpointConnectionError(endpoint_url=request.url, error=e)
botocore.exceptions.EndpointConnectionError: Could not connect to the endpoint URL: "https://ec2.us-east-1.amazonaws.com/"

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/local/lib/python3.11/multiprocessing/process.py", line 314, in _bootstrap
    self.run()
  File "/usr/local/lib/python3.11/multiprocessing/process.py", line 108, in run
    self._target(*self._args, **self._kwargs)
  File "/aws_EC2/master_script.py", line 286, in install_tomcat_on_instances
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_6d.py")
  File "/aws_EC2/master_script.py", line 15, in run_module
    exec(code, globals())
  File "<string>", line 7091, in <module>
  File "<string>", line 6884, in main
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 375, in starmap
    return self._map_async(func, iterable, starmapstar, chunksize).get()
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 774, in get
    raise self._value
botocore.exceptions.EndpointConnectionError: Could not connect to the endpoint URL: https://ec2.us-east-1.amazonaws.com/
```

In summary based upon the test above: 


The system is doing the following: 

- Detects silent failures AWS doesn’t surface
- Flags true ghosts with no PID, no thread UUID, and no registry entry
- Differentiates between swap-induced failures and cloud-side entropy
- Tags synthetic crashes, rehydrated futures, and install success with forensic clarity






## UPDATES part 31: Phase 2o: Fixing the empty security_group_ids list with hyper-scaling tests and ensuring that the security group list is chunked as sg_chunk prior to engaging multi-processing.Pool and calling tomcat_worker_wrapper


### Introduction:

While testing for the adaptive watchdog timeout, it was found to work fine for the 16 node test but when hyperscaling to 
512 nodes (512 processes with 1 thread per process), the security_group_ids list was coming up blank. This caused
the contention penalty to zero out because the SG blocks call retry_with_backoff to assess the number of API re-attempts
and that re-attempt number is used to calculate a max_retry_observed over all the SGs in the process. 

This max_retry_observed is used to calculate the contention_penalty in the adaptive watchdog timeout.  If the SGs are 
blank for all the  nodes, there will be a max_retry_observed of 0 and a 0 contention_penalty.  This only occurs with the 
hyper-scaling test cases.
```
 contention_penalty = min(30, max_retry_observed * 2)  # up to +30s
```
The main reason for this is because the instance metadata needs to use describe_instances with batch processing when
scaling to over 100 instances.   The batch processing staggers the describe_instances requests to AWS so that it can
respond accordingly. The python code logic can use any batch size, but 100 seems to work fine (code will be shown 
below when the code step through is done).

To refactor to this type of instance metadata discover was quite challenging. The standard reservation/response code, 
for example, the block below, had to be retooled to use an orchestrator function that was fortunately already in use and
present. This orcehestrator function was used to wait for all the instances to have status checks passed and to get a
public ip. So leveraging this code made the refactoring in this area much easier. The orchestrator code is very resilient.


The deprecated code consists of blocks like this: 
```
   ###### Block1 goes with Block1b below
    ###### Block1 — legacy reservation logic
    # Retained for backward compatibility and potential tag hydration.
    # SG metadata from this block may be stale or incomplete due to AWS propagation lag.
    # Primary SG resolution now handled via rehydration sweep (see DEBUGX-SG-RESWEEP).
    # Do NOT rely on this block for security_group_ids population — use rehydrated list instead.

    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
    instance_ids = [
        instance['InstanceId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        if instance['InstanceId'] != exclude_instance_id
    ]


    print(f"[DEBUGX-RESERVATIONS] Reservation count = {len(response['Reservations'])}")
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            print(f"[DEBUGX-INSTANCE] ID = {instance['InstanceId']}, SGs = {instance.get('SecurityGroups', [])}")
```

This code is unable to accomodate exremely large numbers of nodes (instances). 

This block below, for example, works fine with a 16 node test but fails (blank) with the 512 node test:



```
    # === Initial SG Sweep (excluding controller) ===
    blank_sg_detected = True  # Assume blank until proven otherwise


    ##### Commenting this block out. This is legacy code and the rehydration code is much more dependable and it is necessary
    ##### for hyper-scaling to 100s of nodes. The code block below works for low number of nodes (for example 16), but it is
    ##### better to have all configurations (16 node, 512 node, etc) go thorugh the same robust code path and use the 
    ##### rehydration code below which is ultimately used to derive all_instances that is used to get the sg_chunk, the per
    ##### process chunk to security group id correlation.
    ##### NOTE: leave the blank_sg_detected = True to force all configurations through the rehydration block below. 
    ##### blank_sg_detected may be used in the future if we require different code paths.

    #for reservation in response['Reservations']:
    #    for instance in reservation['Instances']:
    #        instance_id = instance.get('InstanceId')
    #        if instance_id == exclude_instance_id:
    #            continue  # Skip controller node
    #        sg_list = instance.get('SecurityGroups', [])
    #        print(f"[DEBUGX-SG-FIRSTSWEEP] Instance {instance_id} → SGs: {sg_list}")
    #        if sg_list:  # Found at least one SG on a worker node
    #            blank_sg_detected = False

```


This block fails as well with the 512 node test but works fine for the 16 node test: 

```
    ##### Block1b goes with Block1 above
    ##### Block1b — deprecated SG collection logic
    # This block relied on response['Reservations'], which may be stale or incomplete.
    # SGs now collected via rehydration sweep using instance_ips from orchestrate logic.
    # Commented out to prevent overwriting security_group_ids with partial data.
    # Retained for reference only — do not re-enable unless rehydration fails.

    #security_group_ids = [
    #    sg['GroupId']
    #    for reservation in response['Reservations']
    #    for instance in reservation['Instances']
    #    for sg in instance['SecurityGroups']
    #    if instance['InstanceId'] != exclude_instance_id
    #]
```



Finally, this was the last block that had to be refactored. This failed with 512 nodes but worked with 16 nodes:

```
    ##### This is the code to transform the list security_group_ids to a process level list of security group ids that pertain 
    ##### only to the list of nodes in the chunk that the process is handling.
    ##### The name for this process chunk specific list of security group ids is sg_chunk
    ##### sg_chunks is the full list of per-chunk SG lists — i.e., a list of lists
    ##### sg_chunk is the individual SG list for one chunk
    ##### When zip chunks and sg_chunks, there is a  pairing each chunk with its corresponding SG list
    # each tuple in `args_list` contains:
    #- A chunk of instances
    #- The SGs for those instances
    #- The max worker count

    # This block below is deprecated. It uses the response/reservation block1 stuff and this cannot handle the hyper-scaling
    # hyper-scaling needs to use the orchestator instance blocks above and the describe_instances_metadata_in_batches using
    # batches of 100 each. Otherwise AWS fails to get the complete security_group_ids list and sg_chunks is blank

    #sg_chunks = []
    #for chunk in chunks:
    #    sg_chunk = [
    #        sg['GroupId']
    #        for reservation in response['Reservations']
    #        for instance in reservation['Instances']
    #        for sg in instance['SecurityGroups']
    #        if instance['InstanceId'] in [node['InstanceId'] for node in chunk]
    #        and instance['InstanceId'] != exclude_instance_id
    #    ]
    #    sg_chunks.append(sg_chunk)
```

So from the above, it is clear that there were multiple areas of the code that required refactoring to accomodate the 
hyper-scaling test cases. These blocks above have all been replaced with code that works with very large numbers of 
nodes/processes.

With this new code in place the refactored adaptive watchdog timeout code (see part 30 below) is working extremely well.
On the 512 node test, there are differential contention penalties at the per process level giving each process a 
unique adaptive watchdog timeout based on this API SG contention.  A complete code walk through is below.   Each section follows
logically from the preceeding section. As mentioned above, the orchestrator code that was already present, provided a robust
foundation for the rest of the code.  Getting the security group ids to their respective chunk (process) list of ips would
have been very difficult without this foundaton already in place.


### Methodical code walkthrough: 

Most of the changes in the code were done in main() unless noted otherwise.


#### Section 1: Legacy code retained for backward compatibility. 

The response/reservation code for getting the security group ids of the nodes is deprecated. It does not work when scaling over
100 nodes, and noted in the Introduction above.   The code is below: 

```
    ###### Block1 goes with Block1b below
    ###### Block1 — legacy reservation logic
    # Retained for backward compatibility and potential tag hydration.
    # SG metadata from this block may be stale or incomplete due to AWS propagation lag.
    # Primary SG resolution now handled via rehydration sweep (see DEBUGX-SG-RESWEEP).
    # Do NOT rely on this block for security_group_ids population — use rehydrated list instead.

    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
    instance_ids = [
        instance['InstanceId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        if instance['InstanceId'] != exclude_instance_id
    ]


    print(f"[DEBUGX-RESERVATIONS] Reservation count = {len(response['Reservations'])}")
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            print(f"[DEBUGX-INSTANCE] ID = {instance['InstanceId']}, SGs = {instance.get('SecurityGroups', [])}")
```

There is a Block2 that follows. This is the same type of approach above but using a paginator. 
```
paginator = my_ec2.get_paginator('describe_instances')
```


This did  not resolve the issue with hyper-scaling, and the block2 has been commented out.



#### Section 2: The original orchestrator code using helper function orchestrate_instance_launch_and_ip_polling

This code did not have to be modified but has been included as part of the essential flow of the code that is required
to resolve the hyper-scaling issue.  This code was used instead of using the response/reservation approach in Section 1 above
and this orchestrator provides the foundation for the rest of the code that fixed this issue.


The comments in the code snippet below detail all of the variables that are involved in extracting the data setting up the 
process level correlation of the process chunk list of ips to their respetive security group ids.

Note that this orchestarte_instance_launch_and_ip_pooling is a wrapper function around 2 helper functions: the original
wait_for_all_public_ips and another function that was added to handle large number of nodes, wait_for_instance_visibility.
Both use a recommended 180 second timeout that can be decreased if the instance type is upgraded from t2.micro.


```
####### ORCHESTRATOR instance code: returns instance_ip_data = instance_ips in main() below#############
####### This is used to get instance_ids = rehydration_ids which is passed to describe_instances_metadata_in_batches ########
####### using 100 at a time, to get all_instances which is used to get sg_list (security group per instance id) which ########
####### is used to build security_group_ids, a list of all the security group ids for each node in the entire execution ########
####### run (security_group_ids).  This is later correlated to each process chunk list of ips so that the security group #######
####### rules can be applied to each node in the process. #######

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


        # The new wrapper around wait_for_all_public_ips as AWS is doing batch processing on large EC2 instance launches and
        # the code needs to wait for all the instances to be present and then poll and loop for all public ips to be present
        # the new functions are orchestrate_instance_launch_and_ip_polling and wait_for_instance_visiblilty (default timeout is
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
```


#### Section 3: The new SG (Security Group) sweep and rehydration code to deal with hyper-scaling test cases

The code blocks are below. The comments are self explanatory.
Batch processing that is present in the orchestrate code above has to be used as the foundation for the instance metadata
in hyper-scaling test cases.

The Code Block1b is commented out as it uses the response/reservation code that cannot accommodate hyer-scaling.
```
    ###### New SG Sweep code: This is a patch to troubleshoot hyper-scaling (512 processes) issues with security_group_ids being
    ###### blank.  This only occurs at higher parallel processes.
    ###### The code right above calls orchestrate_instance_launch_and_ip_polling which calls wait_for_instance_visibility and
    ###### then wait_for_all_public_ips. The timemout delay is currently set at 180 seconds on both of these functions. 
    ###### Add another 30 second propagation delay and then perform an initial SG sweep, and if that is still blank do an
    ###### SG re-hydration call to describe_instances_metadata_in_batches to get the sg_list which is 
    ###### per instance SecurityGroups which is then used to create the complete definitve security_group_ids 
    ###### Make sure to exclude the controller node exclude_instance_id when determining if blank_sg_detected


    # === SG Propagation Delay ===
    print("[DEBUGX-SG-DELAY] Sleeping 30s to allow SG propagation...")
    time.sleep(30)



    # === Initial SG Sweep (excluding controller) ===
    blank_sg_detected = True  # Assume blank until proven otherwise


    ##### Commenting this block out. This is legacy code and the rehydration code is much more dependable and it is necessary
    ##### for hyper-scaling to 100s of nodes. The code block below works for low number of nodes (for example 16), but it is
    ##### better to have all configurations (16 node, 512 node, etc) go thorugh the same robust code path and use the 
    ##### rehydration code below which is ultimately used to derive all_instances that is used to get the sg_chunk, the per
    ##### process chunk to security group id correlation.
    ##### NOTE: leave the blank_sg_detected = True to force all configurations through the rehydration block below.
    ##### blank_sg_detected may be used in the future if we require different code paths for different node configurations.

    #for reservation in response['Reservations']:
    #    for instance in reservation['Instances']:
    #        instance_id = instance.get('InstanceId')
    #        if instance_id == exclude_instance_id:
    #            continue  # Skip controller node
    #        sg_list = instance.get('SecurityGroups', [])
    #        print(f"[DEBUGX-SG-FIRSTSWEEP] Instance {instance_id} → SGs: {sg_list}")
    #        if sg_list:  # Found at least one SG on a worker node
    #            blank_sg_detected = False
 

    # === Conditional SG Rehydration Pass ===
    # use instance_ip_data which is returned from the orchestrate_instance_launch_and_ip_polling.
    # main() assigns this to instance_ips
    # rehydration_ids uses this instance_ips to get the instance ids
    # These instance ids are passed to the describe_instances_metadata_in_batches which does the batch processing on the 
    # instances and collects all the metadata for each instance(security group ids, ip address, instance id, etc)

    # This is called all_instances. all_instances will be used to extract a complete security group id list of all the 
    # instances. This is done by first create a per instance id list of security groups called sg_list
    # sg_list provdes the security groups that are associated with each instance id for forensics and troublshooting.
    # sg_list is then used to build the complete definitive list of all the security_group_ids.

    # all_instances is used later to derive the sg_chunk which is the list of security group ids for the chunk list of ips
    # that the current process is handling. This is required in this multiprocessing environment.  This is so that the
    # chunk list of ips can be directly correlated to their security group ids so that we can calculate a per process 
    # API contention when the security group rules are applied to each of the nodes in the process. This API contention is
    # called contention_penalty in the adaptive watchdog timeout, a per process watchdog timeout that is used in the 
    # read_output_with_watchdog that does node output stdout/stderr processing for each node (thread) in the process.
    # This forms the foundation of the thread level forensic logging capability.

    # === Conditional SG Rehydration Pass ===
    security_group_ids = []

    if blank_sg_detected:
        print("[DEBUGX-SG-BLANK] SGs still blank — triggering rehydration pass...")

        def describe_instances_metadata_in_batches(my_ec2, instance_ids):
            all_instances = []
            for i in range(0, len(instance_ids), 100):
                batch = instance_ids[i:i + 100]
                response = my_ec2.describe_instances(InstanceIds=batch)
                all_instances.extend([
                    inst for res in response['Reservations'] for inst in res['Instances']
                ])
            return all_instances

        rehydration_ids = [entry["InstanceId"] for entry in instance_ips]
        # instance_ips is from orchestrate function above. Must use this. From this get the instance ids and then pass
        # this to describe_instances_metdadata_in_batches. 

        all_instances = describe_instances_metadata_in_batches(my_ec2, rehydration_ids)

        for instance in all_instances:
            instance_id = instance.get('InstanceId')
            sg_list = instance.get('SecurityGroups', [])
            print(f"[DEBUGX-SG-RESWEEP] Instance {instance_id} → SGs: {sg_list}")

            #### redefine security_group_ids here and get rid of Block1b legacy code below. Block1b (below) does not work.
            #### See notes below in Block1b
            ###### SG Rehydration — Full List Collection (No Deduplication)
            # Collect security group IDs per instance during rehydration sweep.
            # Preserve full list, including duplicates, to maintain one-to-one mapping with instance_ips.
            # This ensures future compatibility when SGs vary per node — critical for retry logic, chunking, and registry 
            # tagging.
            # Do NOT deduplicate — deduping breaks process-to-SG alignment and undermines traceability.
            # SGs must be ordered and complete to support deterministic orchestration and per-thread rule pushes.

            # Append SGs per instance, even if duplicates
            for sg in sg_list:
                security_group_ids.append(sg["GroupId"])



    ##### Block1b goes with Block1 above
    ##### Block1b — deprecated SG collection logic
    # This block relied on response['Reservations'], which may be stale or incomplete.
    # SGs now collected via rehydration sweep using instance_ips from orchestrate logic.
    # Commented out to prevent overwriting security_group_ids with partial data.
    # Retained for reference only — do not re-enable unless rehydration fails.

    #security_group_ids = [
    #    sg['GroupId']
    #    for reservation in response['Reservations']
    #    for instance in reservation['Instances']
    #    for sg in instance['SecurityGroups']
    #    if instance['InstanceId'] != exclude_instance_id
    #]

```

Some examples of the logging that the above provides is below:


```
[DEBUGX-SG-DELAY] Sleeping 30s to allow SG propagation...
[DEBUGX-SG-BLANK] SGs still blank — triggering rehydration pass...
[DEBUGX-SG-RESWEEP] Instance i-0448c14248832d5dc → SGs: [{'GroupId': 'sg-0a1f89717193f7896', 'GroupName': 'default'}]
[DEBUGX-SG-RESWEEP] Instance i-0cb80d367edb4586c → SGs: [{'GroupId': 'sg-0a1f89717193f7896', 'GroupName': 'default'}]
[DEBUGX-SG-RESWEEP] Instance i-0b3c11fd09c8d5e8e → SGs: [{'GroupId': 'sg-0a1f89717193f7896', 'GroupName': 'default'}]
[DEBUGX-SG-RESWEEP] Instance i-003f197921dc1717d → SGs: [{'GroupId': 'sg-0a1f89717193f7896', 'GroupName': 'default'}]
```

The instance id is listed with its respective sg_list security group id list.




#### Section 4: 

The code between Section 3 and Section 4 below consists of a lot of chunk processing. None of the fundamental process chunk 
code had to be modified.   

The code below is required to derive the sg_chunk that is described in many of the earlier comments above. The sg_chunk is 
the list of security group ids that pertain to the current process chunk list of ips (nodes). This is the ultimate goal, 
because the sg_chunk list of security group ids is applied in tomcat_worker via AWS API to apply the rules to the
security group(s) for the ips (nodes) that the current process is working on. THis AWS API application is what causes
the contention_penalty in the adaptive watchdog timeout, a per process watchdog timeout based upon API contention.

This makes the system as a whole self-adaptive to AWS conditions and will be useful when the Machine Learning layer is
applied to the architecture.


```
    ##### DEBUGX code insertion will be here before the args_list for the SG group id list issue.
    ##### This code is to fix the security_group_ids in the args_list being the full list for ALL the nodes in the execution 
    ##### run. This should not be the case.  It should only be the nodes(threads) in the current process. So if 2 threads per
    ##### process and 16 nodes total over 8 processes, it should be a list of only 2 security group ids,  not all 16
    ##### NOTE: do not change the global security_group_ids, but transform it here and use it in the args_list only.  
    ##### changing the global security_group_ids might disrupt upper level orchestration logic 


    ##### This is the original code, using the security_group_ids (all the node security groups)
    #args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]

    #### Print the original security_group_ids (complete list)  before the tranform to sg_chunk (process level list)
    print(f"[DEBUGX-ORIG-POSTSG-ALL] Full security_group_ids before chunking: {security_group_ids}")


    ##### This is the code to transform the list security_group_ids to a process level list of security group ids that pertain 
    ##### only to the list of nodes in the chunk that the process is handling.
    ##### The name for this process chunk specific list of security group ids is sg_chunk
    ##### sg_chunks is the full list of per-chunk SG lists — i.e., a list of lists
    ##### sg_chunk is the individual SG list for one chunk
    ##### When zip chunks and sg_chunks, there is a  pairing each chunk with its corresponding SG list
    # each tuple in `args_list` contains:
    #- A chunk of instances
    #- The SGs for those instances
    #- The max worker count

    # This block below is deprecated. It uses the response/reservation block1 stuff and this cannot handle the hyper-scaling
    # hyper-scaling needs to use the orchestator instance blocks above and the describe_instances_metadata_in_batches using
    # batches of 100 each. Otherwise AWS fails to get the complete security_group_ids list and sg_chunks is blank

    #sg_chunks = []
    #for chunk in chunks:
    #    sg_chunk = [
    #        sg['GroupId']
    #        for reservation in response['Reservations']
    #        for instance in reservation['Instances']
    #        for sg in instance['SecurityGroups']
    #        if instance['InstanceId'] in [node['InstanceId'] for node in chunk]
    #        and instance['InstanceId'] != exclude_instance_id
    #    ]
    #    sg_chunks.append(sg_chunk)


    ##### This revised chunk to security group id(s) code uses the all_instances from the refactored code above (SG rehydration
    ##### code). This has all of the instances and all of the metadata for each instance via the describe_instances_metadata_in_batches
    ##### function. Here we are simply getting the sg_chunk and sg_chunks. These are the security group ids for each specific
    ##### chunk list of ips (sg_chunk) and chunks (sg_chunks). We need this for process based correlation of the processs
    ##### chunk to their security group ids. See below (zip)
    ##### sg_chunk will be passed to the multiprocessing.Pool via the args_list. See further down below.
    sg_chunks = []
    for chunk in chunks:
        chunk_instance_ids = {node['InstanceId'] for node in chunk}
        sg_chunk = [
            sg['GroupId']
            for instance in all_instances
            if instance['InstanceId'] in chunk_instance_ids and instance['InstanceId'] != exclude_instance_id
            for sg in instance.get('SecurityGroups', [])
        ]
        sg_chunks.append(sg_chunk)



    ##### And create the args_list that is used in the multiprocessing.Pool using this sg_chunk rather than security_group_ids
    ##### The zip will correlate each chunk to the sg_chunk for chunks and sg_chunks.
    args_list = [(chunk, sg_chunk, max_workers) for chunk, sg_chunk in zip(chunks, sg_chunks)]



    #####  DEBUGX-MAIN for the SG issue with hyper-scaling. This has the transformed security group per process chunk list 
    #####  sg_chunk. It prints the process along with the sg_chunk security group id. Note that the process index number
    #####  is NOT the PID. It is just used for print record keeping.
    for i, args in enumerate(args_list):
        #chunk, sg_ids, max_workers = args
        chunk, sg_chunk, max_workers = args
        print(f"[DEBUGX-MAIN-POSTSG-PROCESS] Process {i}: SG IDs = {sg_chunk}")
```



Some examples of the logs printed in the code above are listed below. One can clearly see the transform of the 
full list of security_group_ids to the per process sg_chunk list of security group ids.

It is this process level list of security group ids that are applied to each node in the process (chunk list of ips) as 
rules (see Section 5 below for an example of this code). 

DEBUGX-ORIG-POSTSG-ALL is for a 512 node test. 
```
[DEBUGX-ORIG-POSTSG-ALL] Full security_group_ids before chunking: ['sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896', 'sg-0a1f89717193f7896']
```
Here is the process level chunking. In this test there is 1 thread (node) per process, so there are 512 such log entries.
This is truncated for brevity.
Note that the process numbers are NOT PIDs. These are just indexes for the logging so that the processes can easily be counted
when hyper-scaling. PIDs can be forensically found via the registry_entry for each thread that is created as part of the 
diagnostic artifact logging capability.
For this test only 1 SG per process is being used and it is the same SG. This does not have to be the case.
There is flexiibilty to assign different SGs to blocks of nodes via the nodes that are assigned to the process.

Note that SG assignments are per process.
```
[DEBUGX-MAIN-POSTSG-PROCESS] Process 0: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 1: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 2: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 3: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 4: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 5: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 6: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 7: SG IDs = ['sg-0a1f89717193f7896']
[DEBUGX-MAIN-POSTSG-PROCESS] Process 8: SG IDs = ['sg-0a1f89717193f7896']

(output truncated)

```
 

The args_list in the code above that has this sg_chunk in it is finally used later on in main() when teh multiprocessing.Pool
is called to process the chunk list of ips for the process. As noted throughout this documentation, this 
multiprocessing.Pool calls tomcat_worker_wrapper which calls tomcat_worker which calls threaded_install (via 
run_test) which calls install_tomcat the thread level code which finally calls the read_output_with_watchdog to 
process the node output for STDOUT/STDERR which is used in the foresnsic analysis of the node installation health.


```
    ##### CORE CALL TO THE WORKER THREADS tomcat_worker_wrapper. Wrapped for the process level logging!! ####
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)

```


 

#### Section 5: tomcat_worker function destination where the SG rules are actually applied to the nodes (chunk) for the process

All of the code changes above are in main().

The code below is just presented for completeness, illustrating where the SG rules are actually applied to the nodes 
that are in the chunk for the current process.  Only 1 of the 3 rules is listed below for illustrative purposes.

This code is from the tomcat_worker which is called from the multipprocessing.Pool via the tomcat_worker_wrapper


```
#### [[tomcat_worker]]
#### The new SG blocks of code for the refactored retry_with_backoff. The retry_with_backoff now returns the number of 
#### attempts for the API call to get through for each SG rule application to all the nodes (threads) in the current process
#### This is entirely a process level application.  Each SG rule application will call the retry_with_backoff which will 
#### call the my_ec2.authorize_security_group_ingress AWS API to apply the rules to the nodes. It will retrun the number of
#### attempts which will be recorded as retry_count
#### max_retry_observed will track the maxiumum of all the retry_counts for all the SG rule applications for this process
#### This will capture the **highest retry count** seen across all SG rule applications for THIS PROCESS
#### The final max_retry_observed will then be used to calculate WATCHDOG_TIMEOUT via the call to get_watchdog_timeout
#### (see next block below the SG blocks)


    ###### add DEBUGX for the SG issue at scale that we are seeing. 
    print(f"[DEBUGX-TOMCATWORKER-PROCESS] Entering SG block with security_group_ids = {security_group_ids}")

    for sg_id in set(security_group_ids):
        retry_count =0 # default a fallback for this local variable
        try:
            print(f"[SECURITY GROUP] Applying ingress rule: sg_id={sg_id}, port=22")

            retry_count = retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            print(f"[SECURITY GROUP] Successfully applied port 22 to sg_id={sg_id}")


        except my_ec2.exceptions.ClientError as e:

            if 'InvalidPermission.Duplicate' in str(e):
                print(f"[SECURITY GROUP] Rule already exists for sg_id={sg_id}, port=22")
            else:
                raise  # Let the exception go to the logs. Something seriously went wrong here and the SG rule was not 
                # able to be applied, error is NOT a duplicate rule (we check for that), the process will crash unless
                # this is caught upstream

        # Always update max_retry_observed, even if rule already existed
        max_retry_observed = max(max_retry_observed, retry_count)
        print(f"[RETRY METRIC] sg_id={sg_id}, port=22 → retry_count={retry_count}, max_retry_observed={max_retry_observed}")



    for sg_id in set(security_group_ids):
        retry_count =0 # default a fallback for this local variable
        try:
            print(f"[SECURITY GROUP] Applying ingress rule: sg_id={sg_id}, port=80")

            retry_count = retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            print(f"[SECURITY GROUP] Successfully applied port 80 to sg_id={sg_id}")


        except my_ec2.exceptions.ClientError as e:

            if 'InvalidPermission.Duplicate' in str(e):
                print(f"[SECURITY GROUP] Rule already exists for sg_id={sg_id}, port=80")
            else:
                raise  # Let the exception go to the logs. Something seriously went wrong here and the SG rule was not 
                # able to be applied, error is NOT a duplicate rule (we check for that), the process will crash unless
                # this is caught upstream

        # Always update max_retry_observed, even if rule already existed
        max_retry_observed = max(max_retry_observed, retry_count)
        print(f"[RETRY METRIC] sg_id={sg_id}, port=80 → retry_count={retry_count}, max_retry_observed={max_retry_observed}")
```

This code is realted to the adaptive watchdog timeout code presented in the previous UPDATE. 
The adpative watchdog code has been completely refactored and works very well. The fixes in this UPDATE have completed 
all of the function implementatino in this area.

As the SG rules are applied to the nodes in the process, a max_retry_observed is calculated and this is what feeds into the contention_penalty of the adaptive watchdog timeout formula.

Some examples of the print logs in this area of the code are below: 

The SYNTHETIC injection was used in some of the smaller node test executions.   As shown below at 512 nodes, the API contention
becomes real, with variable max_retry_observed from 1 all the way to 5 or 6.

The watchdog timeout then reflects the contention penalty accordingly at the per process level.

```

[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=22
[RETRY] Wrapper invoked for authorize_security_group_ingress with max_retries=15
[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for authorize_security_group_ingress
[Retry 1] RequestLimitExceeded. Retrying in 1.37s...

[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=22
[RETRY] Wrapper invoked for authorize_security_group_ingress with max_retries=15
[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for authorize_security_group_ingress
[Retry 1] RequestLimitExceeded. Retrying in 1.75s...



[DEBUGX-TOMCATWORKER-PROCESS] Entering SG block with security_group_ids = ['sg-0a1f89717193f7896']
[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=22
[RETRY] Wrapper invoked for authorize_security_group_ingress with max_retries=15
[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for authorize_security_group_ingress
[Retry 1] RequestLimitExceeded. Retrying in 1.83s...
[SECURITY GROUP] Successfully applied port 22 to sg_id=sg-0a1f89717193f7896
[RETRY METRIC] sg_id=sg-0a1f89717193f7896, port=22 → retry_count=1, max_retry_observed=1
[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=80
[RETRY] Wrapper invoked for authorize_security_group_ingress with max_retries=15
[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for authorize_security_group_ingress
[Retry 1] RequestLimitExceeded. Retrying in 1.90s...



[SECURITY GROUP] Successfully applied port 8080 to sg_id=sg-0a1f89717193f7896
[RETRY METRIC] sg_id=sg-0a1f89717193f7896, port=8080 → retry_count=1, max_retry_observed=1
[WATCHDOG METRIC] [PID 17] Final max_retry_observed = 1
[RETRY] Attempt 2 for authorize_security_group_ingress (args=(), kwargs={'GroupId': 'sg-0a1f89717193f7896', 'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 8080, 'ToPort': 8080, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]})
[SECURITY GROUP] Successfully applied port 22 to sg_id=sg-0a1f89717193f7896[DEBUGX-TOMCATWORKER-PROCESS] Entering SG block with security_group_ids = ['sg-0a1f89717193f7896']
[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=22
[RETRY] Wrapper invoked for authorize_security_group_ingress with max_retries=15
[RETRY][SYNTHETIC] Injecting synthetic RequestLimitExceeded for authorize_security_group_ingress
[Retry 1] RequestLimitExceeded. Retrying in 1.97s...

[RETRY] Attempt 2 for authorize_security_group_ingress (args=(), kwargs={'GroupId': 'sg-0a1f89717193f7896', 'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]})
[RETRY] Duplicate rule detected on attempt 2
[SECURITY GROUP] Successfully applied port 80 to sg_id=sg-0a1f89717193f7896
[RETRY METRIC] sg_id=sg-0a1f89717193f7896, port=80 → retry_count=1, max_retry_observed=1
[SECURITY GROUP] Applying ingress rule: sg_id=sg-0a1f89717193f7896, port=8080
[RETRY] Duplicate rule detected on attempt 2
[RETRY] Duplicate rule detected on attempt 2
[DEBUGX-TOMCATWORKER-PROCESS] Entering SG block with security_group_ids = ['sg-0a1f89717193f7896']

<<As the test progresses, more API contention, as shown by max_retry_observed increasing>>

[Dynamic Watchdog] [PID 42] instance_type=t2.micro, node_count=512, max_retry_observed=2 → WATCHDOG_TIMEOUT=96s
[SECURITY GROUP] Successfully applied port 8080 to sg_id=sg-0a1f89717193f7896
[RETRY METRIC] sg_id=sg-0a1f89717193f7896, port=8080 → retry_count=1, max_retry_observed=1





<<different processes are experiencing different API contention>>


[WATCHDOG METRIC] [PID 86] Final max_retry_observed = 2

[WATCHDOG METRIC] [PID 41] Final max_retry_observed = 3


<<the adaptive watchdog timeout values vary with respect to API contention>>


[Dynamic Watchdog] [PID 32] instance_type=t2.micro, node_count=512, max_retry_observed=3 → WATCHDOG_TIMEOUT=98s


[Dynamic Watchdog] [PID 41] instance_type=t2.micro, node_count=512, max_retry_observed=3 → WATCHDOG_TIMEOUT=98s

[Dynamic Watchdog] [PID 63] instance_type=t2.micro, node_count=512, max_retry_observed=4 → WATCHDOG_TIMEOUT=100s

[Dynamic Watchdog] [PID 48] instance_type=t2.micro, node_count=512, max_retry_observed=5 → WATCHDOG_TIMEOUT=102s


[POST-MONITOR METRIC] [PID 174] max_retry_observed = 4

[POST-MONITOR METRIC] [PID 225] max_retry_observed = 3

[POST-MONITOR METRIC] [PID 121] max_retry_observed = 4

[POST-MONITOR METRIC] [PID 401] max_retry_observed = 1


```








## UPDATES part 30: Phase 2n: Refactoring the adaptive watchdog timeout and the API congestion function retry_with_backoff


### Introduction: 

This part of the code needs to be refactored. The WATCHDOG_TIMEOUT is currently defined as a global variable, but it is
actually a per process level setting. The adaptive watchdog timeout will be a per process watchdog timeout. The watchdog
timeout is used in the read_output_with_watchdog which is  thread level raw output orchestrator that is called by 
install_tomcat for STDOUT and STDERR on each node for each thread (always 1 node per thread (IP)).

We want this adaptive and dynamic because there can be a lot of variance in the API contention from process to process.
See earlier updates on all the background on API contention and how the adaptive watchdog was designed.

There are 3 metrics (currently) that go into calculating the adaptive WATCHDOG_TIMEOUT value itself. 

These are in the the get_watchdog_timemout function which is a global module function.

The code is below. The 3 metrics are the following:

- EC2 instance type: smaller instances are slower to respond and, in general, this results in more
API contention at the orchestration layer of the python module, especially if there are hundreds of nodes. 

- A contention penalty is calculated based upon the maximun number of retry attempts for that particular process experienced
across all the threads in that process.  This is not a global retry attempts because the memory is not shared between processes
in python multi-processing. Most of the refactoring was in this area of the code.  A max_retry_observed for each process is
used to record the highest number of API attempts to push the rule(s) in the security group to all the nodes (threads) in 
the process.  This is done across all the security group blocks of code in the tomcat_worker function.

- A base is used for the lower bound of the watchdog timemout.


```
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
#The max_retry_observed will be calcualted per process based upon API contention with AWS (this will be done by a modified
#retry_with_backoff function)
#The scale is a multiplier that is based upon the instance type (higher value for smaller vCPU instance type)
#For initial testing with 512 nodes this will be set to 0.11 so that the watchdog timeout will remain at the original 90 
#second baseline


```
#### CURRENT code issues and the need for refactoring the code:


The current code has several issues. The main issue is that the max_retry_observed is not getting set properly (it stays
at zero regardlless of the amount of RequestLimitExceeded (API contention) experienced. This was verifed by 
creating a synthetic RequestLimitExceeded in the first attempt for each security group rule application in each process
(3 total rules are applied to each node's security group).

The problem was multi-factorial.   The first issue was that both the WATCHDOG_TIMEOUT and the max_retry_observed
were set as global variables. That was the first thing that had to be changed.

Mulit-processing in python dedicates a discrete process memory space per process that is not shared globally. So the
adaptive watchdog timeout has to be designed from the bottom up as a process level variable.

The other cleanup required moving all the WATCHDOG calculations (calls to the get_watchdog_timeout function; see previous
section above), from run_test (that is in tomcat_worker) to tomcat_worker itself.   

#### High level code refactoring design:

The first thing that needed to be done was to set the max_retry_observed =0 at the top of the tomcat_worker function.
This cleanly and clearly establishes it as a local variable and not a global variable.

The next refactoring had to be done to the retry_with backoff function. The objective of this function is to return
the number of attempts that it took to apply the rules with the API rather than returning the results of the API
request itself. The attempt number is what is indicative of the API contention. For testing purposes with the 16 node
setup, a synthetic RequestLimitExceeded was added to bump the attempt from 0 (the initial attempt index number) to
1 so that the contention metric could register a value for testing.   This synthetic injection will be removed once
hyper-scaling testing starts up again.

Once the retry_with_backoff was refactored, the calls to the retry_with_backoff, inside the security group (SG) 
blocks in the tomcat_worker had to be updated.

At this point the tomcat_worker has attempt numbers that are being returned from the calls to retry_with_backoff.
As simple max function is then used to record the highest attempt number encountered across all rull security group
API applications. This is called the max_retry_observed value. Once this value is obtained for the current process
it can be used in a call to the get_watchdog_timeout (see the functino above) to calculate a per process WATCHDOG_TIMEOUT
(The max_retry_boserved is passed as an argument to the get_watchdog_timeout)

Once the WATCHDOG_TIMEOUT has been obtained for that process, this can be passed down through the nested function 
chain all the way down to where it is required in read_output_with_watchdog, the raw output stream orchestrator.

The function call chain arguments all had to have WATCHDOG_TIMEOUT added (this will be shown in the code 
snippets in the sections that follow).   

The chain is: tomcat_worker uses run_test to call threaded_install. So the run_test has to incorporate the 
WATCHDOG_TIMEOUT as an argument.

def run_test needs to have WATCHDOG_TIMEOUT added to its arguments

Next, within run_test, the result is a call to threaded_install and the WATCHDOG_TIMEOUT has to be passed to 
threaded_install through this call. 

def threaded_install needs to have WATCHDOG_TIMEOUT added to its arguments

threaded_install then calls install_tomcat using the ThreadPoolExecutor and the WATCHDOG_TIMEOUT needs to be passed to 
install_tomcat in the futures list: 

```
        #### Add the WATCHDOG_TIMEOUT to the futures list comprehension:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(
                    install_tomcat,
                    ip['PublicIpAddress'],
                    ip['PrivateIpAddress'],
                    ip['InstanceId'],
                    WATCHDOG_TIMEOUT  # ← added here
                )
                for ip in instance_info
            ]

```

Next, def install_tomcat needs to have WATCHDOG_TIMEOUT added to its arguments

install_tomcat calls the raw output orchestrator read_output_with_watchdog which is the final function that actually uses
this WATCHDOG_TIMEOUT at a per thread level. The process level WATCHDOG_TIMEOUT is used for all the threads in the process
when processing the raw output from the commmands that are applied to the nddes (threads) in the process.

The call in install_tomcat is the following: 
```
                   #### Add the WATCHDOG_TIMEOUT to the final read_output_with_watchdog function call
                    stdout_output, stdout_stalled = read_output_with_watchdog(stdout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    stderr_output, stderr_stalled = read_output_with_watchdog(stderr, "STDERR", ip, WATCHDOG_TIMEOUT)
```

def read_output_with_watchdog then used "timeout" internally as the WATCHDOG_TIMEOUT for the processing of the 
raw output from the nodes.
The code for this function did not have to be changed other than using "timeout" as the local variable 



```
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
```


From this flow, once can clearly see that the WATCHDOG_TIMEOUT is a process level variable that is used by 
install_tomcat on each thread in the process when install_tomcat invokes read_output_with_watchdog.

The current issue is related to getting the max retries from the retry_with_backoff at the process level so that it 
can be used to calculate the WATCHDOG_TIMEOUT at the process level. This issue has been fully resolved with the code
refactoring in the sections below. Each refactored function or area of the function is shown and the comments are self
explanatory for the purposes of this README.




### Code refactoring blocks and functions: 

Note: the tomcat_worker, run_test, and threaded_install are process level functions
install_tomcat is a thread level function. 
read_output_with_watchdog  is a thread level function

Both threaded_install and install_tomcat are inside of tomcat_worker
retry_with_backoff and read_output_with_watchdog and run_test are global helper functions


#### retry_with_backoff now returns the attempt for each security group API function call:

```
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

```

#### tomcat_worker security group block calls to retry_with_backoff using the my_ec2.authorize_security_group_ingress API:


There are currently 3 security groups for the 3 rules that are applied to all the nodes (threads) in each process. 
These are done in parallel at the thread level and also at the process level. When hyper-scaling processes this can cause
API contention.


```
#### [[tomcat_worfker]]
#### The new SG blocks of code for the refactored retry_with_backoff. The retry_with_backoff now returns the number of 
#### attempts for the API call to get through for each SG rule application to all the nodes (threads) in the current process
#### This is entirely a process level application.  Each SG rule application will call the retry_with_backoff which will 
#### call the my_ec2.authorize_security_group_ingress AWS API to apply the rules to the nodes. It will retrun the number of
#### attempts which will be recorded as retry_count
#### max_retry_observed will track the maxiumum of all the retry_counts for all the SG rule applications for this process
#### This will capture the **highest retry count** seen across all SG rule applications for THIS PROCESS
#### The final max_retry_observed will then be used to calculate WATCHDOG_TIMEOUT via the call to get_watchdog_timeout
#### (see next block below the SG blocks)




    for sg_id in set(security_group_ids):
        retry_count =0 # default a fallback for this local variable
        try:
            print(f"[SECURITY GROUP] Applying ingress rule: sg_id={sg_id}, port=22")

            retry_count = retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            print(f"[SECURITY GROUP] Successfully applied port 22 to sg_id={sg_id}")


        except my_ec2.exceptions.ClientError as e:

            if 'InvalidPermission.Duplicate' in str(e):
                print(f"[SECURITY GROUP] Rule already exists for sg_id={sg_id}, port=22")
            else:
                raise  # Let the exception go to the logs. Something seriously went wrong here and the SG rule was not 
                # able to be applied, error is NOT a duplicate rule (we check for that), the process will crash unless
                # this is caught upstream

        # Always update max_retry_observed, even if rule already existed
        max_retry_observed = max(max_retry_observed, retry_count)
        print(f"[RETRY METRIC] sg_id={sg_id}, port=22 → retry_count={retry_count}, max_retry_observed={max_retry_observed}")



    for sg_id in set(security_group_ids):
        retry_count =0 # default a fallback for this local variable
        try:
            print(f"[SECURITY GROUP] Applying ingress rule: sg_id={sg_id}, port=80")

            retry_count = retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            print(f"[SECURITY GROUP] Successfully applied port 80 to sg_id={sg_id}")


        except my_ec2.exceptions.ClientError as e:

            if 'InvalidPermission.Duplicate' in str(e):
                print(f"[SECURITY GROUP] Rule already exists for sg_id={sg_id}, port=80")
            else:
                raise  # Let the exception go to the logs. Something seriously went wrong here and the SG rule was not 
                # able to be applied, error is NOT a duplicate rule (we check for that), the process will crash unless
                # this is caught upstream

        # Always update max_retry_observed, even if rule already existed
        max_retry_observed = max(max_retry_observed, retry_count)
        print(f"[RETRY METRIC] sg_id={sg_id}, port=80 → retry_count={retry_count}, max_retry_observed={max_retry_observed}")


    for sg_id in set(security_group_ids):
        retry_count =0 # default a fallback for this local variable
        try:
            print(f"[SECURITY GROUP] Applying ingress rule: sg_id={sg_id}, port=8080")

            retry_count = retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 8080,
                    'ToPort': 8080,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            print(f"[SECURITY GROUP] Successfully applied port 8080 to sg_id={sg_id}")


        except my_ec2.exceptions.ClientError as e:

            if 'InvalidPermission.Duplicate' in str(e):
                print(f"[SECURITY GROUP] Rule already exists for sg_id={sg_id}, port=8080")
            else:
                raise  # Let the exception go to the logs. Something seriously went wrong here and the SG rule was not 
                # able to be applied, error is NOT a duplicate rule (we check for that), the process will crash unless
                # this is caught upstream

        # Always update max_retry_observed, even if rule already existed
        max_retry_observed = max(max_retry_observed, retry_count)
        print(f"[RETRY METRIC] sg_id={sg_id}, port=8080 → retry_count={retry_count}, max_retry_observed={max_retry_observed}")
```






#### removal of the WATCHDOG_TIMEOUT calculation in run_test

All of this code was moved out of the run_test and into the calling funcction tomcat_worker. The WATCHDOG_TIMEOUT is added
to the call to threaded_install from run_test (see below):

```

        # ─── NEW BLOCK  Code block3 for adaptive WATCHDOG_TIMEOUT ───
        # By the time this function is called in tomcat_worker all the  retry_with_backoff calls have happened already in tomcat_worker
        # so max_retry_observed is now set for this process.(modified retry_with_backoff calculates this as max_retry_observed
        # We can compute the dynamic WATCHDOG_TIMEOUT from here with call to get_watchdog_timeout


        ##### WATCHDOG_TIMEOUT is not global. It is calculated per process. Process memory is not shared across processes.

        #global WATCHDOG_TIMEOUT


        # extract node_count from the first arg to func (threaded_install)
        # node_count = len(args[0]) if args and isinstance(args[0], (list, tuple)) else 0
        # instance_type = os.getenv("INSTANCE_TYPE", "micro")



        ###### COMMENT OUT THIS ENTIRE BLOCK. THIS HAS BEEN MOVED TO tomcat_worker right after the SG rule application
        ## Pull node count and instance type from environment
        #node_count = int(os.getenv("max_count", "0"))  # fallback to 0 if not set
        #instance_type = os.getenv("instance_type", "micro")

        ## call the get_watchdog_timeout to calculate the adaptive WATCHDOG_TIMEOUT value
        ## max_retry_observed is iteratively set  in the modified retry_with_backoff functin.
        ##WATCHDOG_TIMEOUT = get_watchdog_timeout(
        ##    node_count=node_count,
        ##    instance_type=instance_type,
        ##    peak_retry_attempts=max_retry_observed
        ##)


        #WATCHDOG_TIMEOUT = get_watchdog_timeout(
        #    node_count=node_count,
        #    instance_type=instance_type,
        #    max_retry_observed=max_retry_observed
        #)
        #
        #print(f"[Dynamic Watchdog] [PID {os.getpid()}] "
        #      f"instance_type={instance_type}, node_count={node_count}, "
        #      f"max_retry_observed={max_retry_observed} → WATCHDOG_TIMEOUT={WATCHDOG_TIMEOUT}s")



        # ─── actual call to threaded_install which returns thread_registry which is process_registry ───
        # thread_registry will be assigned the important process_registry in tomcat_worker() the calling function of run_test

        #result = func(*args, **kwargs)
        # Passing the WATCHDO_TIMEOUT from run_test to func which is threaded_install
        result = func(*args, WATCHDOG_TIMEOUT=WATCHDOG_TIMEOUT, **kwargs)

        print(f"[TRACE][run_test] func returned type: {type(result)}")

        return result  # move this within the benchnark context

```







#### moving the WATCHDOG_TIMEOUT calculation function call (using get_watchdog_timeout) to tomcat_worker and passing the WATCHDOG_TIMEOUT to run_test:


This code block was removed from run_test and moved to tomcat_worker, the parent function. The WATCHDOG_TIMEOUT
will then be passed down to the nested function calls as explained in the earlier section above.


```

    ##### [[tomcat_worker]] add debug prior to the WATCHDOG_TIMEOUT calculation call to get_watchdog_timeout
    #print(f"[WATCHDOG METRIC] [PID {pid}] Final max_retry_observed = {max_retry_observed}")
    print(f"[WATCHDOG METRIC] [PID {os.getpid()}] Final max_retry_observed = {max_retry_observed}")


    ###### ─── Adaptive Watchdog Timeout Calculation ───
    ###### This was moved out of run_test and in tomcat_worker. The WATCHDOG_TIMEOUT can then be easily passed to run_test 
    ###### below.

    # Pull node count and instance type from environment
    node_count = int(os.getenv("max_count", "0"))  # fallback to 0 if not set
    instance_type = os.getenv("instance_type", "micro")

    # Calculate adaptive timeout
    WATCHDOG_TIMEOUT = get_watchdog_timeout(
        node_count=node_count,
        instance_type=instance_type,
        max_retry_observed=max_retry_observed
    )

    print(f"[Dynamic Watchdog] [PID {os.getpid()}] "
          f"instance_type={instance_type}, node_count={node_count}, "
          f"max_retry_observed={max_retry_observed} → WATCHDOG_TIMEOUT={WATCHDOG_TIMEOUT}s")

```

In tomcat_worker the  WATCHDOG_TIMEOUT is then passed to run_test: 

```
    ##### Add the WATCHDOG_TIMEOUT (caclucated earlier in tomcat_worker) as an argument to run_test

    process_registry = run_test("Tomcat Installation Threaded", threaded_install, instance_info, max_workers, WATCHDOG_TIMEOUT=WATCHDOG_TIMEOUT)
```


#### Passing WATCHDOG_TIMEOUT from run_test to threaded_install:

Add WATCHDOG_TIMEOUT to def run_test: 

Note that the func is threaded_install (see section above)

```
def run_test(test_name, func, *args, WATCHDOG_TIMEOUT=None, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):
```


Then pass WATCHDOG_TIMEOUT to threaded_install:

```

        # ─── actual call to threaded_install which returns thread_registry which is process_registry ───
        # thread_registry will be assigned the important process_registry in tomcat_worker() the calling function of run_test

        #result = func(*args, **kwargs)
        # Passing the WATCHDO_TIMEOUT from run_test to func which is threaded_install
        result = func(*args, WATCHDOG_TIMEOUT=WATCHDOG_TIMEOUT, **kwargs)

        print(f"[TRACE][run_test] func returned type: {type(result)}")

        return result  # move this within the benchnark context
```






#### Passing WATCHDOG_TIMEOUT from threaded_install to install_tomcat via the futures list in ThreadPoolExecutor:

Add WATCHDOG_TIKMEOUT to def threaded_install:

```
    # Pass the WATCHDOG_TIMEOUT to threaded_install
    def threaded_install(instance_info, max_workers, WATCHDOG_TIMEOUT=None):
```


Then pass the WATCHDOG_TIMEOUT to install_tomcat via the futures list in ThreadPoolExecutor for per thread use:


```
        #### Add the WATCHDOG_TIMEOUT to the futures list comprehension:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(
                    install_tomcat,
                    ip['PublicIpAddress'],
                    ip['PrivateIpAddress'],
                    ip['InstanceId'],
                    WATCHDOG_TIMEOUT  # ← added here
                )
                for ip in instance_info
            ]

            print(f"[DEBUG] Preparing install_tomcat for {len(instance_info)} instances with WATCHDOG_TIMEOUT={WATCHDOG_TIMEOUT}")

```


#### Passing WATCHDOG_TIMEOUT from install_tomcat to read_output_with_watchdog thread level raw output orchestrator:


Add the WATCHDOG_TIMEOUT to def install_tomcat: 

```
    #def install_tomcat(ip, private_ip, instance_id):
    ##### Add the WATCHDOG_TIMEOUT to the arg list for install_tomcat (passed from the threaded_install ThreadPoolExecutor
    ##### futures list)
    def install_tomcat(ip, private_ip, instance_id, WATCHDOG_TIMEOUT):
        import uuid
        ## install_tomcat is the definitive thread_uuid source. It is removed from calling function threaded_install
        thread_uuid = uuid.uuid4().hex[:8]
```




Call read_output_with_watchdog with WATCHDOG_TIMEOUT argument: 
(this is within the for idx loop and in the for attempt loop)


```
                    #### Add the WATCHDOG_TIMEOUT to the final read_output_with_watchdog function call
                    stdout_output, stdout_stalled = read_output_with_watchdog(stdout, "STDOUT", ip, WATCHDOG_TIMEOUT)
                    stderr_output, stderr_stalled = read_output_with_watchdog(stderr, "STDERR", ip, WATCHDOG_TIMEOUT)
```

Once the read_output_with_watchdog gets the WATCHDOG_TIMEOUT is uses it as "timeout". See the section above on this and the
full snipped of the code.

This is where the adatpive watchdog timeout is actually used, at the thread level for the raw output orchestration from 
each node.







## UPDATES part 29: Phase 2m: Refactoring of the read_output_with_watchdog and install_tomcat continued: Whitelist support for apt and bash and bash-like commands, continue making the code stream agnostic and a general-purpose, resilient command orchestrator:


### Introduction:

This update will contain many areas that need refactoring, namely in the read_output_with_watchdog function and the 
install_tomcat function.

The areas are:

- Log contamination from read_output_with_watchdog and install_tomcat (the calling function)

- Convert the stream based output from read_output_with_watchdog to raw output

- Restructuring and reordering of failure heuritic code in install_tomcat

- Whitelist prototyping with apt commands

- Whitelist extensibility to other bash like commands (using strace) and other package managers (yum, etc.....) (wrapper design) 

- Statistical 512 node testing to refine the whitelist. Running the APT WHITELIST through a few 512 node tests will statistically augment the integrity of the APT WHITELIST greatly.

- Wrapper design and pre-processor design for strace (bash and bash-like) commanands. The pre-processor will identify commands of this type and then wrap them in an strace so that they can be processed through the stderr intelligent parsing.



The main objective of these changes is to create a agnostic command installer and orchestrator that can intelligently detect 
failures in the stderr.




### Log contamination fix:

From the preceeding update

The negative testing of the preceeding section revealed read buffer contamination between the install_tomcat function and the
read_output_with_watchdog function.   Need to consolidate all buffer output flush reads in read_output_with_watchdog
and remove all reads in install_tomcat. 

install_tomcat only needs to be provided with the read output flush from
read_output_with_watchdog, and then install_tomcat has the decision logic (failure, success, and stub logic) to decide
what the registry_entry status of that thread is.  The logic does not need to be changed after this is corrected.

exit_status, the attempt retry count and the STDERR (stderr_output.strip from read_output_with_watchdog) are used
to classify the status of the thread.

Early code:

```

                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0 or stderr_output.strip():
                        print(f"[{ip}] ❌ Command failed — exit status {exit_status}, stderr: {stderr_output.strip()}")

                        if attempt == RETRY_LIMIT - 1:


```

### Convert the stream based output in read_output_with_Watchdog to raw output:

The next area is the conversion of the stream based output flush in read_output_with_watchdog to a raw output. The 
stream based is consistently missing the STDERR channel in the gitlab console logs.   The STDERR provides critial
information for the failure heuristics in install_tomcat (read_output_with_watchdog returns all of this output to 
install_tomcat).   The decision making in install_tomcat needs an overhaul.  Namely whitelist for many STDERR
output that should not be flagged as install_failed or stub.   In addtion the whitelist needs to be adaptabile to 
other applications and commands, not just tomcat9 installations.   So there will be a very large dictionary of output 
phrases that will be used to make the decison of a stub, install_failed or install_success which is based upon the 
command success or failures that are determined in install_tomcat.  The heuritics will eventually include AI based type
techniques to make the decision.

The raw based output refactoring for the read_output_with_watchdog is below:



```

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
```

### Complete restructuring of the failure logic in install_tomcat. (BLOCKS 1 through 5 below)

The next major area of refactoring was a complete restructure and re-ordering of the failure logic. This was done to incorporate
the use of a whitelist (see next paragraph below). 

In short the ordering is:

- Whitelist and whitelist helper function at top of the python module

- In install_tomcat() the stdout/stderr from read_output_with_watchdog (see above; using raw now) (BLOCK1)

- Next block in install_tomcat() move the failure heuristic code to be BEFORE the new whitelist code (BLOCK2)

- Add the new whitelist code and the accompanying failure logic (major update). This utilizes the whitelist and whitelist helper
function at the top of the python module (BLOCK3). This block also has the new code to support strace type commands (bash and 
bash-like commands).

- Keep the legacy resurrection_monitor code hooks for now. (These will be moved and refactored later on; they work at a basic
level) (BLOCK4)

- Default command success logic is the last block.(BLOCK5)  


The high level of the BLOCK insertion is in the "for attempt" loop which is in the "for idx" loop in the install_tomcat
function. See below

This block design has run through several different postive and negative tests with apt and strace(bash and bash-like) command
syntax and has performed well so far.

```
For attempt loop in install_tomcat: (block in parenthesis is the original block order)
    try block
             Stdout/stderr block from read_output_with_watchdog KEEP AS IS BLOCK1(1)
             Move failure heuristics (all of them) here before the new code block with whitelist BLOCK2(4)
             NEW CODE INSERT HERE WITH WHITELIST (this is the latest revision you sent) BLOCK3(2)
             Keep legacy resurrection code for now BLOCK4(3)
             Command succeeded BLOCK5(5)

    except block (keep as is) 

    finally block (keep as is) 
```



#### Whitelist helper function  (The  APT and strace whitelists are reviewed in a section further below):

The whitelists and the helper function are at the top of the module.


```
WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX  # + YUM_WHITELIST_REGEX, etc.

def is_whitelisted_line(line):
    return any(re.match(pattern, line) for pattern in WHITELIST_REGEX)

```




The code blocks in install_tomcat are listed below:

#### BLOCK1:

```
#### BLOCK1(1) is the STDOUT and STDERR output flush from read_output_with_watchdog function

                    #BLOCK1(1)

                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")



                    command = original_command  # original_command is set outside of the "for attempt" loop. See above.
                    # Reset TO before mutation so that the path is reset to /tmp/trace.log for each attempt on the command
                    # that way the command.replace (below) will work for each retry  since /tmp/trace.log remains consistent 
                    # for each re-attempt, and the filename will get a new trace_suffix each time. Without this the trace_suffix 
                    # will remain the same for all command retries because the command.replace will not match for the second
                    # and third retry.


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

                    # strace wrapper debug
                    print(f"[{ip}]  Wrapped processed command(strace debug): {command}")



                    #try pty for debugging
                    #stdin, stdout, stderr = ssh.exec_command(command, timeout=60, get_pty=True)
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
                    
                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)

                    stdout_output, stdout_stalled = read_output_with_watchdog(stdout, "STDOUT", ip)
                    stderr_output, stderr_stalled = read_output_with_watchdog(stderr, "STDERR", ip)

                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")


```


#### BLOCK2:

```
 ## Insert BLOCK2(4) here, before the new whitelist code. This is the failure heuristic code.


 ##### This block BLOCK2(4)needs to be moved after BLOCK1(1) and before BLOCK3(2)
 ##### The failure heuristics can be applied without whitelist filtering as these are known errors

                    # FAILURE HEURISTICS: BLOCK2(4)

                    ## Modify the above to fail ONLY if it is the LAST attempt> we do not want to prematurely create stubs
                    ## and failed registry entries uniless all retries have been exhausted```

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


```




#### BLOCK3: See the sections below concerning whitelist code design specifics.

```
 ##### New whitelist decision making code replacing orignal BLOCK3(2) above. The basic logic constructs are intact with
 ##### the exit_status, RETRY_LIMIT, STDERR output being the main decision making criteria, but also adding in the 
 ##### whitelist as well, for apps that don't behave well with STDOUT and STDERR channel separation.  With these types of
 ##### installs, STDERR is very dirty and needs to be filtered through the whitelist.


                    exit_status = stdout.channel.recv_exit_status()
                    #log.info(f"[{ip}] Raw exit status from SSH channel: {exit_status}") # debug the negative test case issues
                    print(f"[{ip}] Raw exit status from SSH channel: {exit_status}")


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



                    # Revised to support distinct trace.log file names per thread per command per retry
                    tags = []  # ✅ Initialize tags before any strace logic
                    
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



                        #match = re.search(r"\+\+\+ exited with (\d+) \+\+\+", trace_output)
                        #if match:
                        #    exit_status = int(match.group(1))
                        #    print(f"[{ip}] 🔍 Overriding exit status from strace: {exit_status}")



                        ## In the case of forked processes need the FINAL exit status not the interim (test case 5)                   
                        #matches = re.findall(r"\+\+\+ exited with (\d+) \+\+\+", trace_output)
                        #if matches:
                        #    exit_status = int(matches[-1])  # Use the final exit status
                        #    print(f"[{ip}] 🔍 Overriding exit status from strace: {exit_status}")



                        # In the case of background jobs, if the background job exits after the main shell, the exit_status
                        # will be the last item in the strace output, so we cannot simply grep out the last exit_status as above
                        # Must first extract all exit status lines along with their PIDs
                        # Then find the exit status for the original shell PID by grepping for the execve line in the trace_output
                        # If that is found then use that as the exit status. If not use the last exit status in the trace_output

                        # Always fallback to the last exit status if the shell PID is not found by the execve search.

                        # Extract all exit status lines with their PIDs

                        exit_lines = re.findall(r"(\d+)\s+\+\+\+ exited with (\d+) \+\+\+", trace_output)

                        shell_pid = None  # Ensure it's always defined otherwise will get a NameError with certain commands
                        
                        # Try to find the exit status for the original shell PID.
                        # This is the shell PID exit code. This is the one that we want. Grep on execve

                        shell_pid_match = re.search(r"(\d+)\s+execve\(\"/usr/bin/bash\",", trace_output)


                        if shell_pid_match:
                            shell_pid = shell_pid_match.group(1)
                            for pid, status in exit_lines:
                                if pid == shell_pid:
                                    exit_status = int(status)
                                    break
                            else:
                                # Fallback to last exit if shell PID not found
                                if exit_lines:
                                    exit_status = int(exit_lines[-1][1])
                                else:
                                    #exit_status fallback to SSH channel exit_status that was set earlier
                                    tags.append("fallback_exit_status")
                        else:
                            # Fallback to last exit if shell PID not found
                            if exit_lines:
                                exit_status = int(exit_lines[-1][1])
                            else:
                                #exit_status fallback to SSH channel exit_status that was set earlier
                                tags.append("fallback_exit_status")


                        print(f"[{ip}] 🔍 Overriding exit status from strace: {exit_status}")


                        # non_shell exit failure codes (like 1) are flgged with a print below for further investigation
                        # They are not the norm.  The non_shell_failure_tag will be added to the install_success registry
                        # block
                        # Make sure that the shell_pid is defined.
                        non_shell_failures = [
                            (pid, status) for pid, status in exit_lines
                            if shell_pid and pid != shell_pid and int(status) != 0
                        ]
                        
                        # Format tag if needed
                        non_shell_failure_tag = None
                        if non_shell_failures:
                            print(f"[{ip}] ⚠️ Warning: Non-shell PID(s) exited with non-zero status: {non_shell_failures}")
                            non_shell_failure_tag = f"non_shell_exit_failure: {non_shell_failures}"




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
                                            *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]],  # include first few lines for forensic trace
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
                                        *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # First few lines for traceability.
                                        *stderr_output.strip().splitlines()[:25]  # Snapshot for traceability.
                                    ]
                                }
                                #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up trace log
                                ssh.close()
                                return ip, private_ip, registry_entry
                            else:
                                print(f"[{ip}] ⚠️ Unexpected strace stderr — retrying attempt {attempt + 1}")
                                #ssh.exec_command(f"rm -f /tmp/trace_{thread_uuid}.log")  # Clean up before retry
                                time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                                continue



                    ############ non-strace logic: #################

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
                                    *[f"nonwhitelisted_material: {line}" for line in non_whitelisted_lines[:4]], # include first few lines for traceability
                                    *stderr_output.strip().splitlines()[:25]  # snapshot for traceability
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

```

#### BLOCK4:


```
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


```

#### BLOCK5:


```
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

```


### Initial whitelist prototpying with apt commands:

Finally, there is a need for a whitelist fitering of the STDERR output for the reasons outlined below. 

This forms the bulk of the changes. The objectives are to build upon the agnostic output flow analysis to achieve
the following objectives:

- Failure heuristics that reason like a human operator

- Regex-based whitelist filtering to separate noise from signal on dirty STDERR installs (for example apt is notorious 
for STDOUT leakage into STDERR)

- Registry tagging that captures forensic snapshots of each attempt

- This sets the stage for robust resurrection logic that anticipates chaos and builds in recovery

- The above framework is tested with adaptive testing, injecting controlled failures to validate the system’s reasoning
This is where the code is edited to real world scenarios.





### Whitelist extensibility to other package managers and command types (wrapper design):


During failure analysis and negative testing: added a strace whitelist for bash and bash like commands. This effectively
create a stderr channel flow using an strace wrapper around these types of commands that lack native stderr output. This enables
failure filtering for these types of commands.  The prototype is working very well. There will be a wrapper function, and
pre-processing of known bash and bash like commands so that the user does not have to manually apply strace to these types
of commands. It will be automatically done.


The modifications that were made to install_tomcat for this strace whitelist are below. 
These additions were added to the BLOCK3 above
This involves literally injecting the strace error into the stderr_output PRIOR to the whitelist processing and parsing the 
output for non-whitelisted material in the stderr that can be used in the registry_entry for forensics.

```
                    # Revised to support distinct trace.log file names per thread per command per retry
                    
                    tags = []  # ✅ Initialize tags before any strace logic
                    
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

```





The design for  making the whitelist extensible to other package managerslike yum, dnf, and apk is below
Since the stream output is agnostic to the package manager it is only natural to develop the whitelist accordingly.
The proposed code something like this:


```
def is_whitelisted_line(line, tool="apt"):
      regex_map = {
          "apt": APT_WHITELIST_REGEX,
          "yum": YUM_WHITELIST_REGEX,
          ...
      }
      return any(re.match(pattern, line) for pattern in regex_map.get(tool, []))
```
OR this: (this is the method that is currently being used)

```
WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX  # + YUM_WHITELIST_REGEX, etc.

def is_whitelisted_line(line):
    return any(re.match(pattern, line) for pattern in WHITELIST_REGEX)
```




### Running the APT_WHITELIST_REGEX through the 512 node test a few times:

This has shown to improve the integrity of the whitelist greatly. APT is  notorious for not only STDOUT/STDERR leakage but for
the trivial commands that tend to leak into the STDERR. The 512 node tests have revealed a few addtional whitelist items 


Current APT_WHITELIST is below:

```
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


]

```
In general,large-scale testing can drive whitelist evolution from a statistical perspecitve with the APT whitelist given 
that the STDOUT/STDERR cross contamination is entirely non-deterministic.






### Running the strace whitelist STRACE_WHITELIST_REGEX through several methodical test cases


The test cases are designed to test the intricate failure logic with this type of bash and bash-like command syntax.
The test cases have several variants and for now (prior to the strace wrapper function (see next section below)) are manually
wrapped in strace in the commands block of the python module.

At a high level the test cases hit these 4 areas in accordance with testing the failure logic:

| Exit Code | Injected Stderr | Whitelisted? | Expected Outcome |
|-----------|------------------|--------------|------------------|
| 0         | Yes              | ❌ No        | `install_failed` | 
| 0         | Yes              | ✅ Yes       | `install_success |
| ≠ 0       | Yes              | ✅ Yes       | `install_failed` |
| ≠ 0       | Yes              | ❌ No        | `install_failed` |

The non-whitelisted material (Whitelist? No) is inserted as a tag in the thread's registry_entry. The strace STDERR is 
generated by injecting the stface diagnostic output into the STDERR channel so that the "normal" STDOUT/STDERR logic
can be used to analyze the status of the thread.  Also the strace/STDERR is parsed for the exit code and if it is different
from the exit_code of the external python loop, it will be re-written. 

The current STRACE_WHITELIST_REGEX is below but this may change as new data and testing add to the intelligence of the list.

```
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

```


### YUM and DNF regex whitelists for future testing (To be completed):

Since the command processing is application agnostic there is a plan to test this with yum installations on fedora and centos
EC2 instances as well and dnf installations.

The package installers have known signatures, but these whitelists will be refined with the testing process. In particular, 
if the STDOUT and STDERR channels leak between each other (like the APT commands do), the testing will require a high scale
node test (the 512 node test) so that statistically speaking, the whitelist (and non-whitetlisted material for STDERR) can be
refined over time and testing.(see above for the APT WHITELIST result after running with a 512 node test a few times). 

```
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
```


```
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
```

And the aggregated WHITELIST_REGEX that is used in the functions themselves: 


```
WHITELIST_REGEX = APT_WHITELIST_REGEX + STRACE_WHITELIST_REGEX + YUM_WHITELIST_REGEX + DNF_WHITELIST_REGEX

```



### Wrapper design and pre-processor design for bash and bash-like commands using strace as the wrapper:


The pre-processor will identify commands of this type and then wrap them in an strace so that they can be processed through the 
strace intelligent logic for failure analysis. The strace output will be injected into the stderr so that the existing stderr
method of analysis can be applied here. 



#### Wrapper function prerequisite: trace.log isolation

Prior to introducing the wrapper function for this, in BLOCK1 above we introduced the code to ensure that the trace.log
function that is used to store the strace data and inject it into the stderr for further analysis is unique.
It has to be kept unique between threads and within a thread it has to be unique for each command iteration (for idx loop)
and for each retry of each command (for attempt loop). Otherwise there is a risk of cross-contamination of the strace data
that is injected into stderr as the commands and command retries are iterated through for a given thread and across threads
in this multi-threaded environment.  The code is below.


The first block is the helper function and the second block is from BLOCK1 above (at the very beginning of BLOCK1).



```
 ## helper function used for the strace command syntax by the install_tomcat for idx commands/for attempt retry loop
 ## The strace code needs a trace.log file to hold its output prior to injecting it into stderr, and we need to 
 ## have unique trace.log filenames, and this appends a suffix to the trace_suffix.log filename. This prevents cross
 ## log corruption between command execution, retries of command execution at the per thread level. So 
 ## commands and retries all use unique trace.log filenames per thread.

def generate_trace_suffix():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

```


The code below is from BLOCK1 in install_tomcat. This is at the very beginning of the BLOCK1
The wrapper function will contain a generic /tmp/trace.log format and this will be rewritten with the trace_suffix
as indicated below for each command, and for each command retry, per thread ensuring log isolation.

The native commands only require this generic /tmp/trace.log. The pre-processor (see further below) will identify the
native commands that need to be processed and this trace.log will automatically be re-written by the call to generate_trace_suffix
as shown below.

A key requirement is that the command be reintialized to path /tmp/trace.log between command re-attempts. Otherwise the 
second and third attempts will not get unique trace_suffix, but the same suffix as the first attempt.


The pre-processor code will be indicated in the next section below.


```
(outside of the for attempt loop and right before it starts define the original_command that is the wrapped command with the
/tmp/trace.log path)

            original_command = command
            # Snapshot before any mutation.  This ensures that the path /tmp/trace.log 
            # is stored and can be used to reset the path during command re-attempts (see below)


(then proceed with the for attempt loop) 


            for attempt in range(RETRY_LIMIT):
            ## the inner attempt loop will try up to RETRY_LIMIT = 3 number of times to install the particular command
            ## each attempt (of 3) will use the adaptive WATCHDOG_TIMEOUT as a watchdog and if the watchdog expires it
            ## can re-attempt for STALL_RETRY_THRESHOLD =2 number of times watchdogs on each command attemp (of 3 total)

                try:

 #### BLOCK1(1) is the STDOUT and STDERR output flush from read_output_with_watchdog function

                    #BLOCK1(1)

                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")



                    command = original_command  # original_command is set outside of the "for attempt" loop. See above.
                    # Reset TO before mutation so that the path is reset to /tmp/trace.log for each attempt on the command
                    # that way the command.replace (below) will work for each retry  since /tmp/trace.log remains consistent 
                    # for each re-attempt, and the filename will get a new trace_suffix each time. Without this the trace_suffix 
                    # will remain the same for all command retries because the command.replace will not match for the second
                    # and third retry.


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
 
```

So this code above is a necesary part of part of the pre-processing process on these types of commands.

The trace.log file uniqueness has been tested across several different test case scenarios, primarily with failure commands
that instigate the 3 retries (trace.log is unique across all retries for a given command in a given thread), as well as for 
multiple strace commands (successful) that execute in a thread (all have unique trace.log filenames). In addtion, the 
trace.log file names are unique across different threads. So this is a per thread, per command, per retry level of uniqueness
that is required to prevent cross-contamination of the strace injected error data into the stderr channel for each command retry
per thread.

#### Wrapper pre-processor code:
Initial revision: 


```
 ## helper functions for the wrapper for the strace command syntax. The commands[] list will be transformed to 
 ## native_commands (stripped of the strace) so that the user does not have to manually apply the strace transform to the 
 ## commands list.  The suspicious_patterns will be modified accordingly as the testing is done in this area.
 ## The should_wrap is the pre-processor and the wrap_command helper function actually applies the strace transform to the
 ## "native_command"
 ## Note that the /tmp/trace.log is re-written in install_tomcat and a trace_suffix is added to the trace.log name to make each
 ## trace.log unique for each command iterantion and each command retry iteration and unique per thread. This prevents 
 ## cross-contamination since the threads are multi-threaded in parallel and run in parallel processes.


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


```

The suspicious_patterns will be expanded as we test this area of code.


#### The wrapper function:

Note that the -f flag is required in the strace syntax below.   There are some commands that require that the forked subprocesses
be followed to get the necessary strace output (that can then be scrubbed with the whitelist and possibly be tagged as 
non-whitelisted material, so that the installation can be failed).  This occurs with test case 6, a negative python bash like
command string. The error text is in a forked subprocess.

```
def wrap_command(cmd):
    matched = should_wrap(cmd)
    if matched:
        print(f"should_wrap matched: {matched} → Command: {cmd}")
        #return f"strace -e write,execve -o /tmp/trace.log {cmd} 2>/dev/null && cat /tmp/trace.log >&2"

        return f"strace -f -e write,execve -o /tmp/trace.log {cmd} 2>/dev/null && cat /tmp/trace.log >&2"
        
        # -f is needed to follow forked subprocesses. Some commands do this and to get the non-whitelist material from them
        # in the strace output one needs to use the -f flag.
    return cmd
```




#### Rename commands list as native_commands so that the list can be pre-processed and wrapped accordingly by the wrapper function:

This keeps the command pipeline clean and lets `install_tomcat` consume `commands` without any structural changes.
This is placed right before the for idx loop begins, in the install_tomcat function

In the install_tomcat function: 

```


        #### this introduces the wrap command that will look for bash and bash-like commands and wrap them in the strace transform
        #### The helper functions wrap_command and should_wrap and the native_commands list that is from the original commands list
        #### are at the top of this module but later on will modularize the wrap command so that it can be used with other 
        #### service installations like gitlab and mariadb, etc....

        commands = [wrap_command(cmd) for cmd in native_commands]



        #### Beigin the for idx loop which contains the for attempt loop which does the command list iteration
        for idx, command in enumerate(commands):

```


The native_commands list is the commands list stripped of the strace transform. These test cases will need to be run through
the code as a part of the first pass testing in this area. The suspicious_patterns will be modified accordingly as the testing is 
performed.

The commands list and the native_commands list are in the tomcat_worker function  (tomcat_worker calls threaded_install which 
calls intall_tomcat)

The native_commands list changes are below (this is not the complete list)
These will serve as the first pass testing of the wrapper function and the should_wrap (suspicious_patterns) function.

Partial native_commands list: 

```
        #### stripped test cases 1-6 and 8 (raw) without the strace wrapper to test out the new wrapper code wrap_command and
        #### should_wrap

        # Test Case 1: Nonzero exit + nonwhitelisted stderr
        #"sudo bash -c 'echo test > /root/testfile'",

        # Test Case 2: Exit 0 + no stderr (install_success)
        "bash -c 'echo \"hello world\" > /tmp/testfile'",

        # Test Case 3: Nonzero exit + stderr from sudo
        #"sudo touch /root/testfile",

        # Test Case 4: Nonexistent command (exit 127)
        #"bash -c \"nonexistent_command\"",

        # Test Case 5: Script with stderr + exit 1
        #"bash -c \"echo -e '#!/bin/bash\\necho \\\"This is stderr\\\" >&2\\nexit 1' > /tmp/fail.sh && chmod +x /tmp/fail.sh && sudo /tmp/fail.sh\"",

        # Test Case 6: Python stderr injection + exit 0
        #"bash -c \"python3 -c \\\"import os; os.write(2, b'error: something went wrong\\\\n')\\\"; exit 0\"",

        # Test Case 8: Whitelisted stderr + exit 1
        #"bash -c 'echo \"hello world\" > /tmp/testfile; exit 1'",
      


        #- **Test Case 9**: Chained commands — validates that `exit 1` at the end isn’t masked by earlier successes.
        #- **Test Case 10**: Subshell — ensures the wrapper tracks exit from the subshell, not just the parent shell.
        #- **Test Case 11**: Background job — confirms that `exit 1` from the foreground shell isn’t overridden by background process completion.
        #- **Test Case 12**: Pipe — tests whether pipe success masks the final `exit 1`.

  
        # Test Case 9: Chained commands
        #"bash -c 'echo hello && echo world && exit 1'",

        # Test Case 10: Subshell 
        #"bash -c '(echo hello; exit 1)'",

        # Test Case 11: Background Job
        #"bash -c 'sleep 1 & exit 1'",


        # Test Case 12: Pipe
        #"bash -c 'echo hello | grep h; exit 1'"


        # test case 13 failure testing failback logic
        # this will test the fallback logic when fails to find a shell PID
        "python -c \"exit(1)\""



        # test case 14 success 
        #"sh -c \"echo test\""


```


#### Final Regression Test matrix for the strace wrapper implementation:


| Test Case | Description | Status | Key Tags |
|-----------|-------------|--------|----------|
| **1** | Nonzero exit + nonwhitelisted stderr | `install_failed` | `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **2** | Exit 0 + no stderr (3x) | `install_success` | `install_success`, `installation_completed` |
| **3** | Nonzero exit + stderr from sudo | `install_failed` | `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **4** | Nonexistent command (`exit 127`) | `install_failed` | `exit_status_127`, `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **5** | Script with stderr + exit 1 | `install_failed` | `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **6** | Python stderr injection + exit 0 (Test D1) | `install_failed` | `exit_status_zero`, `stderr_detected`, `non_whitelisted_stderr`, `nonwhitelisted_material` |
| **8** | Whitelisted stderr + exit 1 | `install_failed` | `exit_status_1`, `fatal_exit_nonzero`, `stderr_present` |
| **9** | Chained commands ending in `exit 1` | `install_failed` | `exit_status_1`, `fatal_exit_nonzero`, `stderr_present` |
| **10** | Subshell with `exit 1` | `install_failed` | `exit_status_1`, `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **11** | Background job + `exit 1` | `install_failed` | `exit_status_1`, `fatal_exit_nonzero`, `stderr_present` |
| **12** | Pipe + `exit 1` | `install_failed` | `exit_status_1`, `fatal_exit_nonzero`, `stderr_present`, `nonwhitelisted_material` |
| **13** | Silent failure with blank stderr | `stub` | `exit_status_1`, `fallback_exit_status`, `silent_failure`, `exit_status_nonzero_stderr_blank` |
| **14** | Clean success | `install_success` | `install_success`, `installation_completed` |

---

#### Test Case Genearal  Observations:

The code implementation looks robust and is extensible to future changes (if need be based upon hyper-scaling testing)
via the wrapper filter regex and the strace whitelist 

Foresnsic traceablity is very robust via the tags that are in the regsitry_entry for each thread (IP/node). The aggregate
registry_entry  json listing for the entire execution run is part of a much larger logging and reporting infrastructure.
The logging and reporting aggregate and process and thread level orchestration reporting is done via gitlab pipeline artifact log 
files and json files. They are always reported as part of each pipeline run.



- ✅ **Exit code threading** is deterministic across pipes, subshells, and background jobs  
- ✅ **Strace parsing** correctly anchors to shell PID, not line position  
- ✅ **Fallback logic** handles silent exits with no stderr gracefully  
- ✅ **Tag stack** is consistent and forensic-grade across all failure modes  
- ✅ **Retry logic** is uniformly applied (`command_retry_3`) for all failed cases






## UPDATES part 28: Phase 2L: Refactoring of the install_tomcat and the read_output_with_watchdog making the code stream agnostic and a general-purpose, resilient command orchestrator that can install any set of commands on the EC2 nodes

### Introduction:

This code reworks the install_tomcat logic from the thread stream data from the read_output_with_watchdog. Both functions have
been radically modified. The code changes will be indicated below.

The code is now stream agnostic in terms of forensics and falure detection, meaning this can be used to install any application
or package onto the EC2 linux nodes. It is now very extensible, all within this self-learning failure detection and forensic
log framework (Phases 1,2,3 and 4).

The stream detection is now a  **general-purpose, resilient command orchestrator**. The logic is now:

- **Stream-agnostic**: handles verbose and silent commands equally well  

- **Retry-aware**: gives each command a fair chance to succeed  

- **Failure-deterministic**: tags known errors vs. silent failures with forensic clarity (registry_entry with status stub or
install_failed or install_success, etc; and registry_entry has tags for commands and error codes so that in-depth forensics
can be done on failed nodes)
 
- **Extensible**: you can drop in any command sequence — from package installs to service restarts to custom scripts — and the framework will handle it

The orchestration logic has been abstracted from the command semantics, which means we can now layer in new workflows without rewriting core behavior. (modular engineering at its best).

These code changes were very challenging but will provide a  stable foundation to build resurrection logic, ghost detection, and adaptive orchestration on top. (Phase 3 and 4 machine learning).



### High level code changes summary:

There are a lot of complex changes in this area of the code since this area of the code is very critical.

- Retry logic and gating thresholds in install_tomcat and read_output_with_watchdog

- SSH and Command failure and stub detection in install_tomcat based upon output stream from read_output_with_watchdog

- Failure tagging rationale (install_failed vs stub)  See update part 27 below for further detail. The same methodology
has been applied to all additional code here. We only have 4 stub registry_entry thus far. The criteria is very strict.

- Watchdog behavior in read_output_with_watchdog, and STDOUT and STDERR output and giltab console output limiting

- Ensure that the failure registry_entry and stub registry_entry logic only kicks in at the last attempt for both SSH
connections and command attempts in install_tomcat

- Extensibility of command error detection and forensics to arbitrary command sets


The code changes are indicated below (removed code is commented out). The changes were very signficant and the comments
are self-explanatory



### Code changes:


#### read_output_with_watchdog:

The read_output_with_watchdog was significantly modified. 

```
## further optimizations on the waiting for the output to flush from the node. Introduced the grace window.
## The purpose of the watchdog at the thread level is to detect thread output data flush starvation and give the
## thread enough time to collect STDOUT and STDERR for further analysis by install_tomcat (failure/stub detection)
## The stalled indicator below is not used, but is left in for possible future use.  The watchdog in read_output_with_watchdog
## is NOT used for failure detection. Failure detection is done solely based upon the stream detection done in 
## read_output_with_watchodg. Based upon the command semantics and output the decision on whether it is a failure, stub, 
## or success is done in install_tomcat logic based on STDOUT and STDERR of the output flush stream for that command.

def read_output_with_watchdog(stream, label, ip):
    stall_count = 0
    collected = b''
    start = time.time()

    while True:
        if stream.channel.recv_ready():
            try:
                collected += stream.read()
                break
            except Exception as e:
                print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
                break

        elapsed = time.time() - start
        if elapsed > WATCHDOG_TIMEOUT:
            stall_count += 1
            print(f"[{ip}] ⏱️  Watchdog timeout on {label} read. Stall count: {stall_count}")
            if stall_count >= STALL_RETRY_THRESHOLD:
                print(f"[{ip}] 🔄 Stall threshold exceeded on {label}. Breaking loop.")
                break  # Exit loop, but do final flush check below
            start = time.time()

        time.sleep(1)
   ## Final flush attempt after stall threshold. This is the main modification.
    #if stream.channel.recv_ready():
    #    try:
    #        collected += stream.read()
    #        print(f"[{ip}] 📥 Final flush read succeeded on {label}.")
    #    except Exception as e:
    #        print(f"[{ip}] ⚠️ Final read failed after stall threshold on {label}: {e}")



    # After breaking loop due to stall threshold
    flush_deadline = time.time() + 5  # Grace window: 5 seconds
    while time.time() < flush_deadline:
        if stream.channel.recv_ready():
            try:
                chunk = stream.read()
                collected += chunk
                print(f"[{ip}] 📥 Post-loop flush read: {len(chunk)} bytes on {label}")
                break  # Exit early if output arrives
            except Exception as e:
                print(f"[{ip}] ⚠️ Post-loop flush read failed on {label}: {e}")
        time.sleep(0.5)

    ## output limiting. There is no need to collect the entire output stream for purposes of command success or failure.
    output = collected.decode(errors="ignore")
    lines = output.strip().splitlines()
    preview = "\n".join(lines[:3])
    print(f"[{ip}] 🔍 Final output after flush (first {min(len(lines),3)} lines):\n{preview}")



    # Get rid of this and replace with above. This is too verbose.  Need to limit gitlab console logs.  
    #print(f"[{ip}] 🔍 Final output after flush: '{output.strip()}'")


    # the key decision logic is below. The watchdog at this level is to detect thread starvation and not to decide
    # failure, success or stub status (that is done in install_tomcat, the calling function)
    # So this logic is not used. It is left in for possible future use.
    # Logic below:
    #This is the key line:
    #- If we hit the stall threshold **and** the output is blank → `stalled = True`
    #- If we hit the stall threshold **but** got some output → `stalled = False`
    #- If we never hit the stall threshold → `stalled = False`

    #Special case is commands that have no output. They will hit the watchdog attempts threshold and there will be no output 
    #and it will be stalled =True but the logic in install_tomcat will prevent a stub or failed registry_entry due to command 
    #attempt count of 1 (attempt=0) and an exit code of 0 (success). Stub and failed registry_entry in install_tomcat are gated.

    stalled = stall_count >= STALL_RETRY_THRESHOLD and not output.strip()
    return output, stalled

    ## for now "stalled" is not used in the criteria for command success or failure. This logic has been moved to 
    ## install_tomcat. The output stream is the primary artifact from read_output_with_watchdog that is used by
    ## install_tomcat to decide on command success or failure. See install_tomcat, the calling function.
```



#### install_tomcat: 

Likewise, in install_tomcat there were many changes.

The following blocks of install_tomcat were changed.

Note the use of a few stub registry_entry below.  These have no definitive cause or traceback.

For the SSH "for attempt" block (ssh.connect):

```
######### this is the new code for the SSH connection establishment code with registry failure tagging and ###########
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
```


The next major revision to the install_tomcat was in the "for idx" loop for the command installatoin of the application 
(in this case tomcat9; but te code can be used with any command set for any application. Failure and stub detection is
agnostic to the command semantics, and is based on flow detection from read_output_with_watchdog (STDERR and 
exit_status and the current attempt number on the command.   All the old code is commented out below so that the difference 
in the logic can be noted.


```

    for idx, command in enumerate(commands):

        ## the commands are listed at the top of tomcat_worker(), the calling function. There are 4 of them. These can
        ## be modified for any command installation type (any application)

            ## Code for the conidtional registry entry if hit install error: First, Add a success flag before the attempt loop 
            ## set the command_succeeded flag to the default of False BEFORE the for attempt loop
            ## This flag is used to gate the install_failed registry_entry block after the for attempt loop IF
            ## the install_succeeded and break (out of the for attempt loop). This is to prevent a install_failed on
            ## successful installs and preserve the failure logic if the for attempt loop aborts
            command_succeeded = False



            for attempt in range(RETRY_LIMIT):
            ## the inner attempt loop will try up to RETRY_LIMIT = 3 number of times to install the particular command
            ## each attempt (of 3) will use the adaptive WATCHDOG_TIMEOUT as a watchdog and if the watchdog expires it
            ## can re-attempt for STALL_RETRY_THRESHOLD =2 number of times watchdogs on each command attemp (of 3 total)

                try:
                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)

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
                    #    #print(f"[{ip}] ⏱️  Watchdog stall threshold reached — tagging stub for command {idx + 1}/4.")
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


## NEW REVISED CODE:
## Logic:
## | Condition | Action |
##|----------|--------|
##| `exit_status != 0` or `stderr_output.strip()` | Retry (continue) or tag failure depending on attempt |
##| `exit_status == 0` and `stderr_output.strip() == ""` | Mark command as succeeded |
##| After all commands succeed | Tag `install_success` outside the `for idx` loop |
##

## Examples:
##Condition | Outcome | Reason |
##|----------|---------|--------|


## exit_status !=0
##| `stderr_output.strip()` is non-empty AND all command attempts exhausted | `install_failed` | We know what went wrong — stderr gives us the cause |

## exit_status !=0
##| `stderr_output.strip()` is empty AND all command attempts exhausted | `stub` | Silent failure — no output, no clue what happened |   NOTE: this is only our 4th stub. The criteria for a stub is very strict.

## exit_status =0
##| Any attempt succeeds (exit_status=0, no fatal stderr) command succeeded | No need to retry or tag failure . This will bypass all stub and failure registry logic and command succeeded will be reached at the bottom of install_tomcat. If all commands execute in this fashion the registry_entry will be status install_success (outside of the for idx loop).  Note that exit_status is 0 in this case
```

The critical logic is below:
(see the comments above for and explanation and some examples of this flow based logic based on the output from 
read_output_with_watchdog)
Note the stub registry_entry below. Stubs are only used when there is no explicit evidence or trace of the thread 
failure.


```
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0 or stderr_output.strip():
                        print(f"[{ip}] ❌ Command failed — exit status {exit_status}, stderr: {stderr_output.strip()}")

                        if attempt == RETRY_LIMIT - 1:
                            # Final attempt — tag failure
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
                                    "tags": [
                                        "fatal_error",
                                        command,
                                        f"command_retry_{attempt + 1}"  # Optional, for forensic clarity
                                    ]                                   
                        }

                            else:
                                pid = multiprocessing.current_process().pid
                                if pid:
                                    registry_entry = {
                                        "status": "stub",
                                        "attempt": -1,
                                        "pid": pid,
                                        "thread_id": threading.get_ident(),
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": str(datetime.utcnow()),
                                        "tags": ["silent_failure", command]
                                    }
                                    return ip, private_ip, registry_entry
                                else:
                                    print(f"[{ip}] ⚠️ Stub skipped — missing PID on final attempt for silent failure.")
                                    return ip, private_ip, None  # Or fallback logic if needed

                        else:
                            # Retry the command
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue  # the continue is critical. If the retry limit is not reached exit entirely out of this
                        # for attempt loop and go to the next attempt iteration of the same command (give it another try).
                        # all the falure and success logic below will be bypassed which is what we want.

```



The failure heuristics have also been optimized in install_tomcat:
(This is within the for attempt loop that is within the for idx loop)

```
                    # FAILURE HEURISTICS: 

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

                    ## Modify the above to fail ONLY if it is the LAST attempt> we do not want to prematurely create stubs
                    ## and failed registry entries uniless all retries have been exhausted

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
                                "tags": ["fatal_package_missing", command]
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
                                "tags": ["stderr_detected", command]
                            }
                            ssh.close()
                            return ip, private_ip, registry_entry
                        else:
                            print(f"[{ip}] ⚠️ Unexpected stderr — retrying attempt {attempt + 1}")
                            time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                            continue

```

The rest of the install_tomcat function is the same:
(The for idx loop and the for attempt loop (inside of the for idx loop) terminates below)


```
                    print(f"[{ip}] ✅ Command succeeded.")
                    ## set the command_succeeded flag to True if installation of the command x of 4 succeeded
                    ## this will gate the install_failed registry_entry following this "for attempt" block
                    ## The successful install can then proceed to the next for idx command (outer loop) and once
                    ## the for idx loop is done it will proceed through the code to the registry_entry install_succeeded

                    command_succeeded = True

                    time.sleep(20)
                    break  # Success. This is a break out of the for attempt loop. The install_failed registry_entry logic
                    # is gated so that it will not fire if there is this break for Success

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
                        "tags": ["install_for_attempt_loop_abort", f"exception_{type(e).__name__}", command]
                    }
                    return ip, private_ip, registry_entry


                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()
                ## END of the for attempt loop 


            # insert patch7b debug here for the inner attempt for loop
            #print(f"[TRACE][install_tomcat] Attempt loop ended — preparing to return for {ip}")

            ## Keep the trace oustide of the failure block below. This is so that each command will get a TRACE message
            ## For successful commands all four 1/4 through 4/4 will get a print message
            ## For the failure case (if the for attempt loop exhausts after 3 retries), the print will also be done
            # Always print when attempt loop ends — success or failure. Note for the success case for all 4 commands
            # there will be 4 prints for the ip/threas

            #print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip}")

            print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip} — Success flag: {command_succeeded}")


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

<< REST of the install_success logic in install_tomcat() follows >>

```
### Negative test encounter:


Shortly after committing the code changes above, one of the 16 node tests encountered an error. In the gitlab console logs
this showed up as a failed attempt 1 for command 1 of 4, and then the code correcctly retried the command 1 of 4 for 
attempt 2 and succeeded.

The forensics on the initial error illusrate that the code logic above works. Here is the gitlab lab console for the 
error encountered during command 1 of 4 for this particular node:


```
34.236.152.36] 🔍 Final output after flush (first 1 lines):
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
[34.236.152.36] [2025-09-08 01:21:03.421487] STDOUT: ''
[34.236.152.36] [2025-09-08 01:21:03.421521] STDERR: 'WARNING: apt does not have a stable CLI interface. Use with caution in scripts.'
[34.236.152.36] ❌ Command failed — exit status 0, stderr: WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
```


In the code block below the exit_status == 0 because the stderr was not fatal, but the stderr_output.strip() was present
so the code above was entrered and the Command failed message was sent to the console:


```

                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0 or stderr_output.strip():
                        print(f"[{ip}] ❌ Command failed — exit status {exit_status}, stderr: {stderr_output.strip()}")

                        if attempt == RETRY_LIMIT - 1:
                            # Final attempt — tag failure
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
                                    "tags": [
                                        "fatal_error",
                                        command,
                                        f"command_retry_{attempt + 1}"  # Optional, for forensic clarity
                                    ]
                                }
                            else:
                                pid = multiprocessing.current_process().pid
                                if pid:
                                    registry_entry = {
                                        "status": "stub",
                                        "attempt": -1,
                                        "pid": pid,
                                        "thread_id": threading.get_ident(),
                                        "thread_uuid": thread_uuid,
                                        "public_ip": ip,
                                        "private_ip": private_ip,
                                        "timestamp": str(datetime.utcnow()),
                                        "tags": ["silent_failure", command]
                                    }
                                    return ip, private_ip, registry_entry
                                else:
                                    print(f"[{ip}] ⚠️ Stub skipped — missing PID on final attempt for silent failure.")
                                    return ip, private_ip, None  # Or fallback logic if needed                                  
```


However, because it was only the first attempt, the "if attempt == RETRY_LIMIT - 1:" was false and so the install_failed and
the stub registry_entry were NOT created, which is the correct behavior.  Instead the for attempt loop iterated to the 
second attempt for the command 1 of 4, and on the seccond attempt the command succeeded.


This is precisely working as designed.

In summary,

- First attempt of command 1/4 on IP `34.236.152.36` returned:
  - `exit_status == 0` ✅
  - `STDOUT == ''` ❌ (unexpectedly blank)
  - `STDERR == 'WARNING: apt does not have a stable CLI interface...'` ❌

- The logic correctly flagged this as a failure (non-fatal), because:

  ```
  if exit_status != 0 or stderr_output.strip():
  ```
  
That `stderr_output.strip()` triggered the failure path.

- Since it was not the final attempt, the code did not tag `install_failed` or `stub, and instead retried.

- Second attempt succeeded, with full STDOUT captured and no STDERR — tagged as `install_success`.



```
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
```
is technically not fatal, but the logic treats any non-empty STDERR as a signal to retry. That’s intentional because:

- It avoids false positives from noisy package managers
- It ensures clean installs with no warnings or ambiguity
- It gives you deterministic control over what counts as success




### Additional controlled negative testing:

Injection of semantically bad commands or nonfunctional commands:

```
commands = [
        'sudo DEBIAN_FRONTEND=noninteractive apt update -y',

        # second command semantics #
        #'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9',

        #'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat99',

        #'sudo nonexistent_binary --fail', # simulate a runtime crash or exception

        #'sudo bash -c "nonexistent_binary --fail; sleep 1"',  # still an issue with exit_status 5 which does not make sense

        #'bash -c "nonexistent_binary"',  #new test1

        'bash -c \'nonexistent_binary\'',  # new test2


        'sudo systemctl start tomcat9',

        'sudo systemctl enable tomcat9'

```


This part of the negative testing revealed read buffer contamination between the install_tomcat function and the 
read_output_with_watchdog function.   Need to consolidate all buffer output flush reads in read_output_with_watchdog
and remove all reads in install_tomcat. install_tomcat only needs to be provided with the read output flush from 
read_output_with_watchdog, and then install_tomcat has the decision logic (failure, success, and stub logic) to decide
what the registry_entry status of that thread is.  The logic does not need to be changed after this is corrected.

exit_status, the attempt retry count and the STDERR (stderr_output.strip from read_output_with_watchdog) are used
to classify the status of the thread.

```

                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0 or stderr_output.strip():
                        print(f"[{ip}] ❌ Command failed — exit status {exit_status}, stderr: {stderr_output.strip()}")

                        if attempt == RETRY_LIMIT - 1:


```
See the next update above (Phase 2m) for the refactor of read_output_with_watchdog.





## UPDATES part 27: Phase 2k: STUB registry creation for pseudo-ghosts so that they can be tagged as failed and resurrected; also unification of code with thread_uuid for registry indexing


### Introduction:

A true ghost is a thread that has not had a process assigned to it at all. There are some instances whereby the thread
siliently fails and currently the tagging of these types of failures is not in place because there is absoutely no 
registry created for this type of failure. The failure occurs in install_tomcat() typically during the SSH initialization
phase, where the first packet sent out from the python controller (docker container) is sliently dropped. There is no 
acknowledgement from the EC2 node for whatever reason and the thread siliently dies.  It has been discovered that in 
these cases there is no registry created for the thread at all, thus tagging the registry with a status is not possible,
and this thread(ip) will show up as a ghost at the process and aggreaget level when comparing the chunks list of AWS 
IPs to the process_registry or aggregated process registry list of IPs. It will be completely missing.

It is desired to resurrect such threads and the only way to do this is to "capture" the IP in what is called a STUB
registry which is essentially a registry that is created in install_tomcat at the thread level when all else fails and 
the thread simply dies.

This is a gitlab console log of one such failure, what we will eventually tag as ssh_init_failed status:
(finding this entry as noted below was very difficult given that the gitlab log console was over 22MB. The STUB 
registry will make the process much easier in terms of forensics and traceablilty).



Such a failure to connect might show up as an exception in the python gilab pipeline logs as: 

```
dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_168$ grep 184.72.85.254 gitlab_log_pid_reuse_ssh_init_512.txt
[DEBUG] Process 84: IPs = ['184.72.85.254']
[TRACE][install_tomcat] Beginning installation on 184.72.85.254
Attempting to connect to 184.72.85.254 (Attempt 1)
```
This is the complete exchange. Given that the python code reports WATCHDOGS and retries at all levels (SSH connection for
5 retries, install tomcat for 3 retries and a WATCHDOG_THRESHOLD of 2 for each of the install tomcat attempts) normally
scripts have a lot of log information and the registry can easily be tagged with one of the failure statuses.

This case above currently cannot, and it can only be tagged through a STUB registry 



```
Traceback (most recent call last):
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 125, in worker
    result = (True, func(*args, **kwds))
                    ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 51, in starmapstar
    return list(itertools.starmap(args[0], args[1]))
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 603, in tomcat_worker_wrapper
  File "<string>", line 3614, in tomcat_worker
  File "<string>", line 871, in run_test
  File "<string>", line 3516, in threaded_install
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 449, in result
    return self.__get_result()
           ^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/concurrent/futures/_base.py", line 401, in __get_result
    raise self._exception
  File "/usr/local/lib/python3.11/concurrent/futures/thread.py", line 58, in run
    result = self.fn(*self.args, **self.kwargs)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "<string>", line 2930, in install_tomcat
  File "/usr/local/lib/python3.11/site-packages/paramiko/client.py", line 451, in connect
    t.start_client(timeout=timeout)
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 773, in start_client
    raise e
  File "/usr/local/lib/python3.11/site-packages/paramiko/transport.py", line 2201, in run
    ptype, m = self.packetizer.read_message()
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/packet.py", line 496, in read_message
    header = self.read_all(self.__block_size_in, check_rekey=True)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/site-packages/paramiko/packet.py", line 320, in read_all
    raise EOFError()
EOFError



The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/local/lib/python3.11/multiprocessing/process.py", line 314, in _bootstrap
    self.run()
  File "/usr/local/lib/python3.11/multiprocessing/process.py", line 108, in run
    self._target(*self._args, **self._kwargs)
  File "/aws_EC2/master_script.py", line 190, in install_tomcat_on_instances
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_2.py")
  File "/aws_EC2/master_script.py", line 15, in run_module
    exec(code, globals())
  File "<string>", line 4344, in <module>
  File "<string>", line 4170, in main
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 375, in starmap
    return self._map_async(func, iterable, starmapstar, chunksize).get()
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.11/multiprocessing/pool.py", line 774, in get
    raise self._value
EOFError
 [32;1m$ echo "Contents of logs directory after container run:" [0;m
Contents of logs directory after container run:
 [32;1m$ ls -l logs/ [0;m

```

The EOFError: This is see from python Paramiko as a symptom of an SSH handshake failure
It percolates up to the multiprocessing.Pool as shown above


Currently finding these failure threads in a hyper-scaled environment with 100s or 1000s of nodes is difficult and the 
STUB registry along with the tag on the STUB so that the thread shows up in the failed_registry_ips.log file, will make
this process much easier in terms of forensics.


To get this ip in this particular circumstance the following steps were done:

1. **Extract all 512 IPs** from the GitLab debug dump (with the 512 node test the file is massive 22MB of text)
2. **Compare** against the 511 IPs from `benchmark_combinedruntime` or the  PID logs. Through a previous exercise
the PID 97 log file was found to missing the Public IP address, so it was narrowed down to PID97
3. **Find the one IP** that exists in the GitLab debug dump but is missing from the benchmark logs.
4. **Tag it** as the ghost IP — tied to PID 97 or whichever process failed early.

It is a "ghost" but technically not really. The purpose of the STUB registry code will be to tag such threads that 
did get a PID to a STUB registry.   The orchestration code fortunately did create a PID log for the process.

If the thread does not ever get assigned a PID by multiprocessing.Pool then that is a true ghost. That will show up in the missing_registry_ips.log and in the stats as missing ip.

The ssh init failed however will get a stub failure status code (tag) in the stub registry along with the IP address so that
the IP can easily be grepped out in the massive gitlab log for further forensics.


### Proposed STUB architecture:

To make the detection of such corner cases above easier in extremely large hyper-scaled settings with massive large data
sets, the STUB registry will be created as a kind of default directory if all of the other traditional status tagging
logic fails to get a "hit".   

The approach is the following :

Tagged Registry Entries (Normal Failure Cases)
These are real registry entries that were created during execution but tagged with failure states like:
- `"status": "watchdog_timeout"`  
- `"status": "ssh_init_failed"`  
- `"status": "install_failed"`  
- `"status": "stderr_empty"`  

These entries are not stub. They’re valid, hydrated, and traceable — just marked as failed. They contain:
- PID  
- IP  
- `thread_uuid`  
- Possibly partial logs or metadata  



Stub Registry Entries (Last Resort Recovery)
This is the  “fallback forensic patch.” Similar to the example in the introduction.  A stub is:
- Created only when no registry entry exists 
- Based on AWS control plane data (i.e. chunk IP, maybe PID)  
- Used when all tagging logic fails and the node is missing from process_registry (for whatever reason, like the example 
above  
- Hydrated with minimal info: PID, IP, maybe a guessed `thread_uuid`  
- Tagged as `"status": "stub_created"` or `"status": "unknown_failure"`  


This is a forensic safety net.


Very simple logic flow (this is not actual code that will be used. The failure detection code will be fairly complex)

At the top level, look for a registry entry, and then if none, require that a pid be assigned to the thread/IP. Otherwise
we want the call to create_stub_registry to fail and let the existing ghost detection logic (which uses AWS control plane
chunk IP data and compares to process_registry and aggregate registry) kick in.


```
if registry_entry_exists(ip):
    tag_registry(ip, status="ssh_init_failed")
else:
    create_stub_registry(ip, pid, status="stub_created")
```


Basically tag if you can and only STUB if you must, but it has to have a PID assigned.

During post-mortem triage:
- IPs with no registry and no PID → ghosts
- IPs with registry but `"status": "failed"` → resurrectable
- IPs with stub registry and PID → fallback recovery candidates

A three-tiered forensic map:
1. Tagged failures  
2. Stubbed unknowns  
3. True ghosts


To prevent the case in the introduction from crashing the create_stub_registry function above, add simple logic to
require the pid, otherwise return and let the robust chunk based ghost detection logic already in place handl the 
IP/thread. That thread with no PID is a true ghost.  The case above in the intro is not a true ghost and will get a
fabricated STUB registry entry with its ip address, PID and a status indicating it is a stub based failed thread that
is a suitable candidate for resurrection.


```
def maybe_create_stub_registry(ip, pid, thread_uuid=None):
    if not pid:
        return  # Let ghost detection handle it
    create_stub_registry(ip, pid, thread_uuid)
```


In summary, the stub example above serves as a prime example of the application use of the stub directory.  It's use is 
not confined to this scenario above.   Any scenario that meets the criteria of the PID assigned, no registry created, and
therefore no status tagged (in the pre-stub code implementation) is suitable for stub registry assignment.

| Scenario                      | PID Assigned | Status Tagged | Registry Created | Stub Logic Triggered |
|------------------------------|--------------|----------------|------------------|-----------------------|
| Install Success              | ✅           | ✅              | ✅                | ❌                    |
| SSH Retry Failure (5x)       | ✅           | ✅ (patch8)     | ✅                | ❌                    |
| SSH Init Drop (no response)  | ✅           | ❌              | ❌                | ✅                    |
| No PID Assigned              | ❌           | ❌              | ❌                | ❌ → ghost detection  |


As noted above, the stub will make the forensic back tracing of these types of thread issues much easier.

The second and third examples above are both suitable for resurrection of the original thread, with perhaps a new
thread_uuid. (That is part of Phase 3 of this project). The major point is that we do not want the SSH init drop
issue, for example, to be classified as a ghost and in the missing_registry_ips.log file, but rather we want it 
to be classified as a failed thread in the failed_registry_ips.log file.


In install_tomcat where half of the stub logic will be (the other half will be in threaded_install, the function that
calls install_tomcat), there are some additional scnearios to incorporate for the stub. In install_tomcat there is 
an SSH loop (5 retries) to establish the SSH connection to the node, and then there is the tomcat command installation
loop (3 retries) that python issues to the node after the SSH connection is up (to install tomcat).  Inside this install
retry loop (each attempted loop) there is a watchdog stall (2 watchdogs failed).  All the stalls as notied in the table
below will be failure tagged (the code is not there yet, but they will be) and they will be listed in the 
failed_registry_ips.log.   

The SSH int drop (detailed above) will trigger a stub, and it will also be classified in the failed_registry_ips.log

The tomcat command drop (no output) (I have not seen this to date) will trigger a stub, and it will be classified
in the failed_registry_ips.log

The rest of the bad thread scenarios will be caught by the ghost detection logic. These typically don't even have a 
PID assigned and their only forensic traceability is in the AWS control plane chunk data. The ghost detection logic
works at both the process and the aggregate main() level to classify in the missing_registry_ips.

Of note, all of these threads are potential resurrection candidates except for the ghosts (missing_registry_ips.log).
(the last row in the table below)

Looking a bit ahead to the implementation of the explicit failure tagging(patch 8), the rows 2, 3, and 4 will be 
explicitly failure tagged. Rows 5 and 6 will be stubs. Row 7 will be the ghosts.


| Scenario                          | PID Assigned | Status Tagged         | Registry Created       | Stub Triggered |
|----------------------------------|--------------|------------------------|------------------------|----------------|
| Install Success                  | ✅           | ✅                     | ✅                     | ❌              |
| SSH Retry Exhaustion (5x)        | ✅           | ❌ (currently)         | ✅ (patch8)            | ❌              |
| Tomcat Install Retry Exhaustion  | ✅           | ✅ (mis-tagged)        | ✅                     | ❌              |
| Watchdog Stall (2x)              | ✅           | ✅                     | ✅                     | ❌              |
| SSH Init Drop (no response)      | ✅           | ❌                     | ❌                     | ✅              |
| Tomcat Command Drop (no output)  | ✅           | ❌                     | ❌                     | ✅              |
| No PID Assigned                  | ❌           | ❌                     | ❌                     | ❌ → ghost logic|





### Why the registry is currently not created in the SSH init drop case?

- The thread is spawned  
- PID is assigned  
- IP is provisioned  
- First SSH packet is sent  
- **No response at all** — not even a timeout  
- The thread hits an **EOFError or socket-level exception**  
- The function install_tomcat() exits prematurely — before reaching any registry hydration logic for registry_entry or
before reaching the end of the install_tomcat() return function whereby the registry_entry is returned to threaded_install
for the process registry listing thread_registry. In either case there is no registry_entry for the thread.


If the function hits an EOFError or socket-level failure, and it’s not caught by `except`, then:

- The function exits immediately  
- No registry is created  
- No return statement is reached  
- Control returns to `threaded_install()` with a `None` or malformed result

This is exactly what happened in the `ssh_init_failed` case. The thread was alive, had a PID, but never returned a 
registry entry.





### Stub code placement:


#### in threaded_install():

This function needs stub logic right after the ThreadPoolExecutor invocation of install_tomcat()
The purpose here is to catch any catostropic thread failure in install_tomcat() as this will cause an abrupt exit
to the calling function threaded_install().   See above more a more complete description.

This should catch any abrupt exit in either the ssh.connect code in instalL_tomcat or the installaton code in install_tomat
(for "for idx" loop or the "for attempt" loop)

The code insertion point is shown below:


The first part of the for future block has to be commented out as shown below:


```
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

```


#### in install_tomcat():

This function needs stub logic in one area, in the first SSH retry 5 loop. Regarding the "for idx" loop and the 
"for attempt" loop  for the installation of tomcat (3 retries with threshold of 2 watchdogs on each retry), there
is no stub logic required as all exists are accounted for by errors or exeptions. However the stub protection in 
threaded_install will cover an abrupt exit from the "for idx" loop or the "for attempt" loop if they are silent and 
code flow returns to the calling function.

For the first part (the SSH retry 5 loop) the stub logic is inserted after the for/else block as shown in the next section
below.

The original code below is completely commented out (the original for/else blocK) because there is addtional failure logic
added within the for/else block.


```
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
```



### Code Implementation:

The stub code and failure status logic needs to be incorporated into 2 different areas in the code: The first in the
threaded_install() function and the second in the install_tomcat() function.  The threaded_install function is a process
level function and the install_tomcat function is a thread level function.

It is important to note that the thread_uuid as the uniqe key to the aggregate registry, is only generated in the 
install_tomcat function. The special stub_uuid is a fabricated uuid just for the purposes of filling in the keying material
for the stub registry in the threaded_install because it has no thread_uuid generation. This is ok as the stub created
in the threaded_install is a very rare event and the likelihood of a collision between the stub_uuid value and a 
thread_uuid value is very very low.



#### threaded_install():

After commenting out the first part of the for futures block as noted above, the new code is inserted below.
The later part of this block below is basically the same except for a 1 line rewrite of the "undefined" tag
just to make it clear how it is used.


```
          for future in as_completed(futures):
                try:
                    ip, private_ip, registry_entry = future.result()
                    pid = multiprocessing.current_process().pid

                    if registry_entry and "thread_uuid" in registry_entry:
                        thread_registry[registry_entry["thread_uuid"]] = registry_entry
                        thread_uuid = registry_entry["thread_uuid"]

                    else:
                        # Silent failure — no registry returned
                        pid = multiprocessing.current_process().pid
                        if pid:
                            stub_uuid = uuid.uuid4().hex[:8]
                            stub_entry = {
                                "status": "stub",
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
```





#### install_tomcat():

There  are two areas that need stub registry protection in the install_tomcat() function. 


##### (1a) SSH connect:


The first is the for/else loop (5 retries) that is used to establish the SSH connection to the node.

The stub code is below the for/else block. The for/else block has addtional logic added to it for various failure
scenarios with a tag/status provided to the registry_entry:


The "status": "ssh_retry_failed" tag is a deterministic failure outcome, not a stub. It’s the expected forensic tag when all 5 SSH attempts are exhausted. That’s part of the core logic, not fallback behavior.

The "status": "stub" tag, on the other hand, is reserved for:

- Silent exits (EOF, socket drops, or thread aborts without registry hydration)

- Unexpected gaps in artifact creation or PID traceability

- Any thread that vanishes without triggering the retry logic or install flow

Note the important break in the "for try" block"  This will occur if there is a successful ssh connect.
The ssh_success flag is set to True only in this case. This flag is to prevent a stub registry assignment.

The break will cause execution to move to the next block outside of the for/else block which is the 
stub block right below it. The stub block has very stringent conditions as described above: The code requires
status is not tagged and no registry created and False on the ssh_success flag.  The first 2 are met but the 
third condition fails so the stub registry is correctly NOT applied to a successful ssh connection.

The code execution proceeds to the for idx loop and the 4 commands are issues over the SSH connection to install
tomcat9

All the way at the end of the install_tomcat() function, providing that tomcat is successfully installed (The 
for idx loop), the registry will be created for this thread/ip and the status will be set to install_success.


```

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
                ssh.connect(ip, port, username, key_filename=key_path)
                ssh_connected = True
                ssh_success = True  # suppress stub
                break
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                print(f"Connection failed: {e}")
                time.sleep(10)
        else:
            print(f"Failed to connect to {ip} after multiple attempts")
            registry_entry = {
                "status": "ssh_retry_failed",
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
                print(f"[STUB] install_tomcat exited early for {ip}")
                stub_entry = {
                    "status": "stub",
                    "pid": pid,
                    "thread_id": threading.get_ident(),
                    "thread_uuid": thread_uuid,
                    "public_ip": ip,
                    "private_ip": private_ip,
                    "timestamp": str(datetime.utcnow()),
                    "tags": ["stub", "early_exit"]
                }
                return ip, private_ip, stub_entry
```



##### (1b) Watchdog timeout in  the ssh.connect for/try block:

In testing the above fix, the code did not cause any breakage in install_tomcat but teh 512 node test revealed interesting
data. There were 3 "failures". One was a true ghost (missing_registry_ips, where the AWS control plane chunk IP of the
thread completely vanished. No PID assigned, no Attempting to connect, etc).

The other 2 were similar to the EOF failure detailed in the introduction, but there were no exceptions in the gitlab
log. So the print:               print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")
is in the gitlab logs and there is an attempting to connect but that is all the evidence of the IP.

The PID is assigned as well, but the benchmark pid log has a missing ip by the time the orchestrator logging tracks it
The IP is listed in the gold IP AWS control plane list of deployed EC2 instances.
This is what made tracking this thread so easy.



Here are the gitlab logs of one such occurrence:

```
[TRACE][install_tomcat] Beginning installation on 34.204.0.244
Attempting to connect to 34.204.0.244 (Attempt 1) <<<<<<
```

Since there is no exception in paramilo.ssh, the existing stub code outside of the for/else block is never reached,
and the install_tomcat() function never returns to threaded_install() for that stub to kick in. So no stub was created

These 2 failures do have a PID so a stub should be created for them.

For example, the first thread:
```
[Patch7d] 👻 Ghost detected in process 45: 34.204.0.244
```
Here we finally get the PID. It is 45.

Looking at the PID45 logs we see this:


Here is the benchmark PID 45 log. It is very similar to the EOF failure in that there is no Public IP (but there was in the gold chunk list)


```
2025-08-26 00:55:36,303 - 45 - MainThread - Test log entry to ensure file is created.
2025-08-26 00:55:41,444 - 45 - MainThread - [PID 45] START: Tomcat Installation Threaded
2025-08-26 00:55:41,458 - 45 - MainThread - [PID 45] Initial swap usage: 1.28 GB
2025-08-26 00:55:41,458 - 45 - MainThread - [PID 45] Initial CPU usage: 0.00%
2025-08-26 00:58:15,335 - 45 - Thread-4 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-08-26 00:58:35,900 - 45 - MainThread - [PID 45] END: Tomcat Installation Threaded
2025-08-26 00:58:35,937 - 45 - MainThread - [PID 45] Final swap usage: 21.83 GB
2025-08-26 00:58:35,937 - 45 - MainThread - [PID 45] Final CPU usage: 0.00%
2025-08-26 00:58:35,937 - 45 - MainThread - [PID 45] Total runtime: 174.02 seconds
```

The PID json registry file has nothing in it:
{}


The only way to create a stub for this type of failed thread is to add this code inside the for/try block as shown below:

The timeout of 30 seconds will need to be emprically tested so that it is a resonable watchdog timeout without creating
false stub entries (failures)


NOTE: the watchdog thread itself can have an exception. This is not a big deal, it just means that the watchdog thread
won't be active for that particular thread and it won't be offering any type of timeout/stub protection.   However, just
because the watchdog for a thread has an exception, does not mean that the worker install tomcat thread is affected. In the
512 node test I saw on watchdog thread exception and added the tryp/except block below, inside of the watchdog, to print
out more information to the gitlab console logs in case this happens again in the future.

```

for attempt in range(5):
    try:
        print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")

        # Start a watchdog timer in a separate thread. This is to catch mysterious thread drops and create a stub entry for those.
        # The status of stub will make them show up in the failed_ips_list rather than missing 
        
	def watchdog():
	    try:
		time.sleep(30)
		if not ssh_connected:
		    pid = multiprocessing.current_process().pid
		    if pid:
			stub_entry = {
			    "status": "stub",
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

        ssh.connect(ip, port, username, key_filename=key_path)
        ssh_connected = True
        ssh_success = True
        break

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(f"Connection failed: {e}")
        time.sleep(10)
```







##### (2) Installation of tomcat (not stubs):

Although this area of code with the "for idx" loop and the "for attempt" loop seems like it would have a need for 
stubs, after coding the protection in this area, it was found that all of the registry_entry code was non-stub, i.e.
there were reasons as to why the thread failed and so install_failed status code could be applied to the registry_entry

The examples of this coverage are below.  All the errors are install_failed status code and attributed to direct causes
like the "for attempt" loop retry expiring (count of 3 attempts per command of the "for idx" loop; each attempt having a
watchdog threshold of 2), or an install command failing, or an exception in the "for attemp" try/except block.  

As shown in the code samples below, these registry_entry are status install_failedwith the following tags:

```
"tags": ["fatal_package_missing", command]
"tags": ["exception_RuntimeError", command]
"tags": [f"install_failed_command_{idx}", command]
```


The stub registry is not required here because any abrupt silent exit will be picked up by the stub code in threaded_install
(see above for that code), the calling function.

This area of code requires a major overhaul. There is a lot of legacy code and the resurrection_registry is  no longer
required. Instead the process_registry needs to be used. 
The logical issues with the code have been corrected in this area, but the resurrecction_registry and gatekeeper
changes will be done in separate updates in the fture.
A lot of the resurrection code will be moved to the resurrection_monitor function which continues to be developed in
preparation for Phase3 of this project.


The code block incorporating all the changes for failure registry_entry is below. The extensive comments make this 
self-explanatory. Note there is an outer loop (for idx) that controls the command iteration (in this case 4 commands, 
but this can be used to adopt any installaton dynamic), and an inner loop inside each idx loop (for attempt loop)
that executes each command. There are 3 retries per command allowed with 2 watchdog timeouts max per command retry.
So the failure code is deisgned around this structure.

```
 for idx, command in enumerate(commands):

        ## the commands are listed at the top of tomcat_worker(), the calling function. There are 4 of them. These can
        ## be modified for any command installation type (any application)

            ## Code for the conidtional registry entry if hit install error: First, Add a success flag before the attempt loop 
            ## set the command_succeeded flag to the default of False BEFORE the for attempt loop
            ## This flag is used to gate the install_failed registry_entry block after the for attempt loop IF
            ## the install_succeeded and break (out of the for attempt loop). This is to prevent a install_failed on
            ## successful installs and preserve the failure logic if the for attempt loop aborts
            command_succeeded = False



            for attempt in range(RETRY_LIMIT):
            ## the inner attempt loop will try up to RETRY_LIMIT = 3 number of times to install the particular command
            ## each attempt (of 3) will use the adaptive WATCHDOG_TIMEOUT as a watchdog and if the watchdog expires it
            ## can re-attempt for STALL_RETRY_THRESHOLD =2 number of times watchdogs on each command attemp (of 3 total)

                try:
                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)

                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)

                    stdout_output = read_output_with_watchdog(stdout, "STDOUT", ip, attempt)
                    stderr_output = read_output_with_watchdog(stderr, "STDERR", ip, attempt)

                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")


                    ## Insert the call to the resurrection_gatekeeper here now that read_output_with_watchdog has collected all the relevant 
                    ## arguments for this function call

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

                    # 🔴 Fatal error: missing tomcat9 package — tag and return
                    if "E: Package 'tomcat9'" in stderr_output:
                        print(f"[{ip}] ❌ Tomcat install failure — package not found.")
                        registry_entry = {
                            "status": "install_failed",
                            "attempt": attempt,
                            "pid": multiprocessing.current_process().pid,
                            "thread_id": threading.get_ident(),
                            "thread_uuid": thread_uuid,
                            "public_ip": ip,
                            "private_ip": private_ip,
                            "timestamp": str(datetime.utcnow()),
                            "tags": ["fatal_package_missing", command]
                        }
                        ssh.close()
                        return ip, private_ip, registry_entry


                    #if "E: Package 'tomcat9'" in stderr_output:
                    #    print(f"[{ip}] ❌ Tomcat install failure.")
                    #    ssh.close()
                    #    return ip, private_ip, False
                    #    # this error is a critical error so return to calling thread but need to set registry



                    # ⚠️ Non-fatal warning — clear stderr and proceed
                    if "WARNING:" in stderr_output:
                        print(f"[{ip}] ⚠️ Warning ignored: {stderr_output.strip()}")
                        stderr_output = ""
                        # clear the stderr output



                    # ⚠️ Unexpected stderr — retry instead of exiting
                    if stderr_output.strip():
                        #print(f"[{ip}] ❌ Non-warning stderr received.")
                        
                        #ssh.close()
                        #return ip, private_ip, False
                        # this is not a criitical error. Will set a continue to give another retry (of 3) instead
                        # of ssh.close and return to calling function

                        print(f"[{ip}] ❌ Unexpected stderr received — retrying: {stderr_output.strip()}")
                        continue  # Retry the attempt loop



                    print(f"[{ip}] ✅ Command succeeded.")
                    ## set the command_succeeded flag to True if installation of the command x of 4 succeeded
                    ## this will gate the install_failed registry_entry following this "for attempt" block
                    ## The successful install can then proceed to the next for idx command (outer loop) and once
                    ## the for idx loop is done it will proceed through the code to the registry_entry install_succeeded
                    command_succeeded = True

                    time.sleep(20)
                    break  # Success. This is a break out of the for attempt loop. The install_failed registry_entry logic
                    # is gated so that it will not fire if there is this break for Success

                except Exception as e:
                    print(f"[{ip}] 💥 Exception during exec_command (Attempt {attempt + 1}): {e}")
                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)
                    # Tag as install_failed with exception details. This is part of the traceability for the install_tomcat
                    # thread forensics.  
                    registry_entry = {
                        "status": "install_failed",
                        "attempt": attempt,
                        "pid": multiprocessing.current_process().pid,
                        "thread_id": threading.get_ident(),
                        "thread_uuid": thread_uuid,
                        "public_ip": ip,
                        "private_ip": private_ip,
                        "timestamp": str(datetime.utcnow()),
                        "tags": ["install_for_attempt_loop_abort", f"exception_{type(e).__name__}", command]
                    }
                    return ip, private_ip, registry_entry


                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()
                ## END of the for attempt loop 

            # insert patch7b debug here for the inner attempt for loop
            #print(f"[TRACE][install_tomcat] Attempt loop ended — preparing to return for {ip}")

            ## Keep the trace oustide of the failure block below. This is so that each command will get a TRACE message
            ## For successful commands all four 1/4 through 4/4 will get a print message
            ## For the failure case (if the for attempt loop exhausts after 3 retries), the print will also be done
            # Always print when attempt loop ends — success or failure. Note for the success case for all 4 commands
            # there will be 4 prints for the ip/threas
            
            #print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip}")

            print(f"[TRACE][install_tomcat] Attempt loop exited for command {idx + 1}/4: '{command}' on IP {ip} — Success flag: {command_succeeded}")


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

       registry_entry = {
            "status": "install_success",
            "attempt": 0,
            "timestamp": str(datetime.utcnow()),
            "pid": multiprocessing.current_process().pid,
            "thread_id": threading.get_ident(),
            "thread_uuid": thread_uuid,
            "public_ip": ip,
            "private_ip": private_ip
        }

        # debug for patch7c 
        print(f"[TRACE][install_tomcat] Returning install result for {ip}")

        print(f"Installation completed on {ip}")

        # make sure to return this registry_entry for this thread instance to threaded_install
        return ip, private_ip, registry_entry

```





### Summary of stub logic:

The stub is a very selective and narrow regitry_entry reserved only for very special circumstances. To date there are only
3 areas of code that are usin stub code, 2 of them in the install_tomcat ssh.connect code as noted above and one in the
threaded_install calling function.  There will be future additions of stub code as needed when hyper-scaling testing 
resumes.

#### layers of protection for registry_entry forensics:

The registry_entry is the most detailed form of forensics in the log artifacts.   The objective is:
Layers of logic protection in install_tomcat and threaded_install for forensic thread integrity and traceablity.
There are two main layers, one in install_tomcat with varaious stub and failure registry_entry logic and the second layer
in threaded_install with the stub logic to track silent failures the abruptly exit install_tomcat and go back to 
threaded_install. In addtion there are various watchdogs in install_tomcat as well and corresponding stub registry entries
for those test cases. As the hyper-scaling ramps up there will be addtional stubs added to the code for forensic tracking.


#### Definition of a stub:

The definition of a stub was mentioned several times.  This is a summary of the definition so that the stub is never used
when an applicable failure registry_entry with causation can be used.

The objective is always to minimize the number of ghost threads, the threads that are missing and vanish when compared
to the gold ip AWS control plane list of EC2 instances.

What a “Stub” Really Means

In this architecture, a **stub** is a placeholder registry entry created when:
- The thread exits without completing its intended logic  
- There's **no definitive status** like `install_failed` or `ssh_retry_failed`  
- The failure is **silent or ambiguous** — no stdout, no stderr, no traceback

Examples:
- SSH init fails before connection — no command ever runs - caught by stub 
- Watchdog times out during connect — no output captured - caught by watchdog timers and stub
- A thread exits without returning a registry — caught by `threaded_install` stub logic

These are true stubs: they represent **absence of information**, not a known failure.

Why an Exception Is *Not* a Stub

When an exception is raised inside the `for attempt` try/except loop block (for example):
- There is  a traceback  
- There is knowledge of the  command that failed  
- The registry_entry can have a status of `install_failed` and include the exception type in the tags

That’s not a stub — it’s a **classified failure** with forensic traceability.











## UPDATES part 26: Phase 2j: Refactoring the aggregation level ghost detection code with the chunks in main() as GOLD standard



### Introduction:

After the existing benchmark_ips and benchmark_ips_artifact.log code was modularized in UPDATES part 25 below, it was found
that the benchmark pid logs that are used to create the benchmark_combined_runtome.log was susceptible to not catching
all of the IPs that are provisioned during the AWS setup and condtrol plane. This was found through an ssh init failed
thread that showed up as missing in the benchmark_ps list.  The ssh init failed case will be reviewd in the next update
in detail.  Nonetheless, the benchmark_ips cannot be used as a GOLD ip list when implementing process level
 ghost detection code.

 In Update part 24 below, the process level was instrumented to use the chunk from chunks which is created in main() during
the AWS control plane provisioning stage of the AWS instances.  In like fashion the aggregate level code for ghost detection
needs to use chunks (plural) from main() as the GOLD ip list when implementing aggregate ghost detection code.

The benchmark_ips and benchmark_ips_artifact.log data is deprecated for ghost detection purposes, but the code has not
been commented out because it still may have a good future use.



### Code changes to refactor using chunks rather than benchmark_ips as the GOLD ip list in aggregate ghost detection 

Note that this code will be implemented in the resurrection_monitor_patch7d function. That is where the benchmark_ips
code is as well (see UPDATES part 25 below).

The first code change is to create a global helper function 
This function gets chunks from the calling function main() 


This is the helper function at the top of the python module.
It is using the same chunks that is defined in main(). The main() code is listed below this helper function
snippet.

Helper function:

```
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

```



As decribed below, chunks are all the IPs of length  chunk_size, that serve as individual chunks of IPs for each
process when multiprocessing.Pool provisions the multi-processing for the execution run.

Simplified, from main(), chunks is defined in main() here:





```
### Configurable parameters
    chunk_size = 1 # Number of IPs per process
    max_workers = 1  # Threads per process
    desired_count = 487  # Max concurrent processes for iniital batch

    chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
```
The call to the helper function is then done right after chunks is defined in main() as this:


```
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

```

The multiprocessing.Pool engine is engaged when passing the args_list to tomcat_worker_wrapper through
the pool.startmap. The args list has this same chunks list. So in using the chunks as the GOLD ip list
we are getting the source AWS control plane provisioned IPs of all the instances prior to being processed
by the multiprocessor and mult-threading engines (in threaded_install).  This is why it is such a robust
source of truth for detecting ghost threads.


```
args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]
...
try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
```


Finally, the deprecated benchmark_ips that was formerly the gold standard, needs to be replaced by this
list of chunk sourced gold IPs (aggregate_gold_ips) in  the main() aggregated ghost detection 
code and logic. The key replacment line is noted with <<<<<<< in the large code snippet below.
the replacement is here:

```
        #missing_ips = benchmark_ips - total_ips
        #### aggregate gold ips from chunks ####
        missing_ips = aggregate_gold_ips - total_ips
```

The complete code block is below. It is a bit complex but in short the final_registry is the real time actual
list of all the registry entries for the entire execution run (derived from each pid process_registry)
This final_registry is flattened out into a sorted ip list. This serves as the real time list of all the threads/ips
that have actual registry entries. This is assigned total_ips. The total_ips is then finally compared to the
aggregate_gold_ips list that was created above with the new helper function (this is the gold aggreegate ip list
derived from all the AWS control plane chunks).  The diff is missing_ips which is essentially the list of ghosts
assigned as: ghosts = sorted(missing_ips)

This ghosts is then used to output both the log and json artifact log files to the gitlab pipeline for easy
forensic analysis.

Note that all of these changes are done in the write-to-disk main() refactoring that was done earlier (see earlier
update below). The entire aggreagate write-to-disk block is within a finally block following the call to the
multiprocessing.Pool above. So at this point one can clearly see the clean and logical aspects of this design.


```
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
    finally:

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
        missing_ips = aggregate_gold_ips - total_ips <<<<<<<<<<<<<<<



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
```


Thus at this point all of the code has been refactored at both the aggregated top level (as indicated above) in main() 
using chunks and also at the process level in resurrection_monitor_patch7d using chunk (process level; see update part 24 
below), as the GOLD ip list.  This makes detection of ghosts very accurate and forensically traceable. The ghost, as 
explained in detail in Update part 27 above, is a very narrow and rare thread failure case, that has never even been
 assigned an PID (hence the source of truth has to be before the call to multiprocessing.Pool as explained above).

This code has been postively tested, but the negative test with actual ghosts will be done at a later time once 
I return to the hyper-scale process testing.  





## UPDATES part 25: Phase 2i: Refactoring the benchmark_ips and benchmark_ips_artifact.log creation in resurrection_monitor_patch7d with a modular function


### Introduction:

Note that this code is deprecated but still has potential future use.  The helper function is hydrate_benchmark_ips() and is
called from resurrection_monitor_patch7d. The modularization will help clean up the resurrection monitor function that
still has a lot of legacy code in it.



### Code changes:

The first step in modularizing this code in resurrection_monitor_patch7d is to comment out the old code.
In the python module this is noted as the following comment:

```
##### Begin comment out of old benchmark_ips  code.
##### This is the old benchmark_ips generation code.This has been replaced by the global modular function above
##### as part of patch 7d2, hydrate_benchmark_ips()
##### All of this code needs to be commented out after adding the call to hydrate_benchmark_ips early in the 
##### res mon function (see above)
```

This is a large block of code that not only includes the core logic for calculating the benchmark_ips list and the
benchmark_ips_artifact.log file, but also a lot of logging and deprecated stats logic (for failed, missing, total, 
and succesful ips) that is now done in main() at the aggregate level.





The next step involmves creating a new global helper function hydrate_benchmark_ips() to remove some of the bulk
in resurrection_monitor and clean up the code.



```
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
```



The third step involes getting this function (this is defined within the resurrection_monitor_patch7d function so 
it is not a global function) from the old benchmark_ips code that was commented out. This function still needs
to be used.

This function is placed near the top of the resurrection_monitor_patch7d function so that it can be used
later in the code.

```
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
        return benchmark_combined_path```
```



The fourth step involves wiring or hooking this helper function into the resurrection_monitor_patch7d now that
most of the the old benchmark_ip code has been commented out.

Note that this code must be added AFTER the patch7.logger has been initialized, etc. 

Note that the first line calls the combine_benchmark_logs_runtime(log_dir, patch7_logger).
patch7_logger has to be passed to the function because it does write to the logger to the gitlab console

The helper function hydrate_benchmark_ips uses this benchmark_combined_path when it creates the benchmark_ips

The call to the helper function is made through the benchmark_ips = hydrate_benchmark_ips(log_dir)

Once the benchmark_ips is returned by the hyrdate_benchmark_ips, it can be used to create the artifact 
benchmark_ips_artifact.log in the log_dir, which is mounted from the docker container to the gitlab /logs directory
so that the artifact can be downloaed directly from the pipeline.

This has been tested an is working well.


```
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

```





## UPDATES part 24: Phase 2h: resurrection_monitor_patch7d1 fix for the ghost json logging fix using instance_info (chunk) for PROCESS level GOLD ip list for ghost detection 

(This code will be modularized using helper function detect_ghosts() at a later time)



### Introduction:

The ghost detection at the per process leve needs to be revised. The issue is that the current IP list that is being used to
detect missing ips from the registry is for the global execution aggregate level.  The requirement is for the thread ip list
that has been assigned to the current process that is using the resurrection_monitor (the resurrection_monitor function is 
called through the tomcat_worker function at the process level after the process_registry for the process has been formed).

The GOLD standard thread ip list (the list of EC2 instance ips from the original batch created on AWS in module1 of the 
python package) is in the instance_info list.

The instance_info list has the following etiology:


Recall that main calls tomcat_worker_wrapper which calls tomcat_worker which calls threaded_install and threaded_install, 
through the ThreadPool_Executor calls install_tomcat at the thread level.  tomcat_worker calls threaded_install through
a helper process named run_test.  Because tomacat_worker and run_test and threaded_install are at the process level, they
are the ideal place to grab the process level list of IPs that were originally created by AWS and assigned to the process by
the main() function call to tomcat_worker_wrapper at this line of code:

```
try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
```

The args_list that is passed to tomcat_worker_wrapper has this:

```
args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]
```


This args_list has the chunk of ips that are assigned to a pariticular process that the multiprocessing.Pool will use when
calling the tomcat_worker_wrapper function.

The chunk is derived as follows:

```
### Configurable parameters
    chunk_size = 2   # Number of IPs per process
    max_workers = 2    # Threads per process
    desired_count = 6   # Max concurrent processes for iniital batch

    chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]


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
```

This chunk list of ips is mapped to a list called instance_info when the call is made to tomcat_worker_wrapper:

```
def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
```


This instance_nfo is the list of IPs to which to compare the process process_registry list of threads to determine if there
are any IPs (threads) completely missing (no status/tag, no reccord of the thread at all; this can happen under some rare
circumstances, for example the EC2 node never comes up to running state). This is the definition of a true ghost thread.
These threads are NOT the same as resurrection candidate threads/registry entries. Resurrection candidates have registry 
entries in the process_registry but for whatever reason (we will get into tags/status) they have some sort of failed status.
Ghosts have no entry in the process_registry hence the reliance upon the instance_info as a GOLD standard to detect them.

Given that tomcat_worker_wrapper calls tomcat_worker, some minor changes need to be made in tomcat_worker when it calls
threaded_install through the run_test helper function.

### Refactored code blocks


##### resurrection_monitor_patch7d:

First change is to pass the instance_info described above, essentailly the chunk of IPs designated to be worked on by
the threads in the process, to the resurrection_monitor to scan for ghosts.

```
def resurrection_monitor_patch7d(process_registry, assigned_ips, log_dir="/aws_EC2/logs"):
```

Thus the function is now defined with an assigned_ips local argument which as shown below maps to the instance_info of the
calling function in tomcat_install

The new ghost detection logic in the resurrection_monitor_patch7d is below:
(This code will be modularized into the helper function detect_ghosts() at a later time)

```
        ####################
        ## insert patch7d fixes:
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
```

This effectively compares the process.registry for the process to this assigned_ips (instance_info) list of ips to detect
if any threads have completely fallen out of the process_registry

The ghosts are then exported as an artifact to the gitlab pipeline as resurrection_ghost_missing_{pid}.json at the per
process level.

Note that there is an aggregate ghost json file generated at the main() level but this uses a GOLD list of all the 
ips (threads) for the entire execution runtime list (benchmark_ips) and compares that to an aggregated list of all the 
process_registry log files (this is detailed in an earlier update as write-to-disk implementation).

 

##### tomcat_worker(), run_test() and threaded_install() functions:

tomcat_worker_wrapper has the instance_info as one of its arguments (see above)
When tomcat_worker_wrapper calls tomcat_worker it does so by this:

```
return tomcat_worker(instance_info, security_group_ids, max_workers)
```


Thus tomcat_worker now has the instance_info.

tomcat_woker calls threaded_install and assign process_registry for the process with this line where we need to explicitly
pass this instance_info to threaded_install (via run_test)

```
   # For resurrection_monitor_patch7d need to pass instance_info and max_workers because i have chnaged the 
    # def threaded_install from threaded_install() to def threaded_install(instance_info, max_workers). Another option
    # is to revert back to threaded_install() and then the change below is not required. I will use the args for clarity.
    
    process_registry = run_test("Tomcat Installation Threaded", threaded_install, instance_info, max_workers)
```

This change to add the args to threaded_install was not mandatory because threaded_install is defined inside of tomcat_worker 
scope, but I decided to add the args so that the code arg requirements could be more easily followed.

run_test is already defined to handle any args passed to it with the `*args`:


```
`def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):`

```
The test_name is threaded_install.

Finally. threaded_install has the following def:

```
    ## For patch7d of resurrection_monitor add the args to the threaded install function. This is not absolutely required
    ## since threaded_install and install_tomcat are both inside of tomcat_worker which has these 2 args but adding it
    ## for clarity sake. instance_info or chunk or assigned_ips is required for per process ghost detection.
    
    def threaded_install(instance_info, max_workers):
```



#### Call to the resurrection_monitor function from tomcat_worker():

The resurrection monitor function is called from tomcat_worker right soon after the process_registry has been assigned
(see above), and this requires that the instance_info arg be added so that the new code in it (see above) can work with this 
IP list as the process level GOLD standard IP list to compare the process_registry list to.

```
    ##### patch7d: add the argument chunk which is instance_info which will be assigned_ips in the resurrection_monitor_patch7d
    ##### function. This is required so that we have a GOLD ip list of what should be processed by the thread in the process
    ##### Real time process_registry entries missing from that list of ips are ghosts.
    ##### After `threaded_install()` returns `process_registry`, pass both `process_registry` and `instance_info` 
    ##### (which is the assigned chunk) to the monitor:

    resurrection_monitor_patch7d(process_registry, instance_info)
```

instance_info maps to the internal arg assigned_ips in the resurrection monitor function
This is used in the new code block in the section above to find the list of ghost ips.
This has been tested with at 16 node simple exeution run but needs to be negative tested with real ghosts during the 
hyper-scaling process test runs. At 16 nodes there are obviously no ghost threads and that is what the process level 
ghost files demonstrated (no files were created at the process level)








### Summary from the module2 comments:


```
######## patch7d ##########
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
```







## UPDATES part 23: Implementation of the control plane Public IP orchestrator


### Introduction:

During the hyper-scaling testing, at some point the code was unable to accomodate and detect when all of the Public IPs were
assigned to all of the nodes (EC2 instances). This occurred during the implementations of Updates part 21 and 22 where there
was no scale process level testing and the tests were only with a small number of EC2 instances (12-16).

Once scale testing was resumed this issue surfaced, but this issue was not present during prior hyper-scaling testing.
It appears that AWS is doing some sort of staggered batch processing when a very large number of EC2 instances are launched
all at the same time. The python launching code is in module 1 of the package, whereas the updates in this README mostly 
pertain to the module2 code.   Thus the fix for this involved a minor change to module 1 (added tagging to all of the AWS
instances in the launched batch), and a much larger change to module 2 to accomodate this staggered batch like Public IP
assignment to the nodes.

The behavior of the defect with the orignal code was strange.  16 and 32 nodes continued to work fine but scaling beyond 32
caused an issue where the code would get stuck waiting for all the Public IPs to be assigned (even long after they had actually
been assigned by AWS).
Note in the debugs below that the message is stating 513 of 0 which does not make sense. So the code was getting tangled up.

Initially, I thought the write-to-disk or adaptive watchdog timeout changes caused the issue,but after reverting the code 
to prior to those commits and seeing the same problem,it was determined that there was a change in the way AWS is deploying 
and assigned Public IPs with very large batches of launched EC2 instances.


In the gitlab logs this showed up as:


```
[DEBUG] Attempt 1: Checking public IPs... [DEBUG] 1 of 0 instances have public IPs. Retrying in 5 seconds... 
[DEBUG] Attempt 2: Checking public IPs... [DEBUG] 1 of 0 instances have public IPs. Retrying in 10 seconds... [
DEBUG] Attempt 3: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 20 seconds... [
DEBUG] Attempt 4: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 30 seconds... [
DEBUG] Attempt 5: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 30 seconds... 
[DEBUG] Attempt 6: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 30 seconds... 
[DEBUG] Attempt 7: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 30 seconds... 
[DEBUG] Attempt 8: Checking public IPs... [DEBUG] 513 of 0 instances have public IPs. Retrying in 30 seconds... [
ERROR] Not all instances received public IPs within 180 seconds.

```


These messages were pointing to an issue with the control plane setup function wait_for_all_public_ips()


There is a timeout that is passed to this function and I tried increasing it from 120-180 seconds (which worked before even
with hyper-scaling) to 300 seconds, but it did not resolve the issue. The issue was more complex than simply waiting longer
for the all the public IPs to actually come up. The code was getting confused based on the batched nature of the Pubilc IP 
asisgnments.

After adding several debugs to the wait_for_public_ips function this was showing up:

This is with a 128 node setup:


```

[DEBUG ENTRY1] wait_for_all_public_ips
    raw instance_ids:         ['i-0c52a587c73f0e183', 'i-0c86a35ea5ec3277b', 'i-00aded7c7224bfeaa', 'i-04d7b6d44d1e69655', 'i-04ed838790605533d', 'i-08d40c2acd4b07d2f', 'i-03fa484fab1b501ab', 'i-022858441c3608b81', 'i-0c9f08b8e05db7e30', 'i-0b584c4bd52a5550f', 'i-0accb9be1427b6cdd', 'i-0d88638157b004abd', 'i-0dde60ec821b99f35', 'i-0b3aeb8afb6b2e0fa', 'i-06dd44f5459822be2', 'i-00b4e557e5536a971', 'i-07a3c2c9ec22e4522', 'i-06bea644676f07f4a', 'i-002d19a85830b70f1', 'i-03eb17e5672a4c3c1', 'i-0efb5219daa05f38e', 'i-04fa425a551540667', 'i-02dab600ed9e15d3e']
    exclude_instance_id arg:  'i-0aaaa1aa8907a9b78'
[DEBUG1] filtered_instance_ids → ['i-0c52a587c73f0e183', 'i-0c86a35ea5ec3277b', 'i-00aded7c7224bfeaa', 'i-04d7b6d44d1e69655', 'i-04ed838790605533d', 'i-08d40c2acd4b07d2f', 'i-03fa484fab1b501ab', 'i-022858441c3608b81', 'i-0c9f08b8e05db7e30', 'i-0b584c4bd52a5550f', 'i-0accb9be1427b6cdd', 'i-0d88638157b004abd', 'i-0dde60ec821b99f35', 'i-0b3aeb8afb6b2e0fa', 'i-06dd44f5459822be2', 'i-00b4e557e5536a971', 'i-07a3c2c9ec22e4522', 'i-06bea644676f07f4a', 'i-002d19a85830b70f1', 'i-03eb17e5672a4c3c1', 'i-0efb5219daa05f38e', 'i-04fa425a551540667', 'i-02dab600ed9e15d3e']
[DEBUG1] count of filtered IDs → 23
[DEBUG] Attempt 1: Checking public IPs...
[DEBUG1] Launch response keys → dict_keys(['Reservations', 'ResponseMetadata'])
[DEBUG1] Number of Reservations → 1
[DEBUG1] Instance ID → i-0c52a587c73f0e183
[DEBUG1] Public IP → 3.87.240.175
[DEBUG1] State → running
[DEBUG1] Instance ID → i-0c86a35ea5ec3277b
[DEBUG1] Public IP → 54.234.82.64
[DEBUG1] State → running
[INFO] All 23 instances have public IPs.
[DEBUG] instance_ips initialized with 23 entries
[DEBUG] Null or missing IPs: []
2025-08-14 03:17:56,780 - 8 - INFO - [MAIN] Total processes: 23
Process2: install_tomcat_on_instances: [MAIN] Total processes: 23
2025-08-14 03:17:56,781 - 8 - INFO - [MAIN] Initial batch (desired_count): 128
Process2: install_tomcat_on_instances: [MAIN] Initial batch (desired_count): 128
2025-08-14 03:17:56,781 - 8 - INFO - [MAIN] Remaining processes to pool: -105
Process2: install_tomcat_on_instances: [MAIN] Remaining processes to pool: -105
[DEBUG] Process 0: chunk size = 1
```
It is clear here that the code thinks that 23 Public IP addreses assigned is adequate for a 128 node launch.  The code
is not checking the Public IP assigned count to the configured node count (max_count from the .env variables in the 
gitlab-ci.yml pipeline file). Because of the staggered assignment this was now surfacing.  So the original function
wait_for_all_public_ips first needed to be wrapped in an orchestator function to address this issue.  The orchestrator
would use a new function, wait_for_instance_visibility to ensure that all the instances that are expected to be launched
are actually up and running before engaging in the wait_for_all_public_ips check that makes sure that they all have 
Public IPs. This wasy, the wait_for_public_ips code does NOT have to be changed at all.

wait_for_instance_visiblity does the following:
```
# Waits until all expected EC2 instances are visible via describe_instances.
# Uses exponential backoff and filters by tag and state.
# Returns a list of instance IDs once the expected count is reached.
```
The filtering by tag and state also requires that EC2 instance tagging be used in module1 (the python EC2 node launching
code). That way the wait_for_instance_visibility can filter only on these instances if the region has other instances for
other purposes.

The DEBUG trace also revealed another issue. So the 128 node test above actually proceeded with 23 processes (of the intended
128) and installed tomcat on the instances.   The 512 test completely aborted. So with this fix above I was not sure if it
would fix the 512 test scenario as well. After testing, it was found that this fix below in its entirety did fix the 512
node case as well.


#### Code additions and changes:


As mentioned above the wait_for_public_ips function did not have to changed for this fix.

```
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
```


This is the new helper function wait_for_instance_visiblity:



```
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
```




This is the wrapper function (orchestator) around the wait_for_public_ips:


```
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
```





In main() replace the call to wait_for_all_public_ips with the wrapper orchestate_instance_launch_and_ip_polling:


```
      #instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, exclude_instance_id=exclude_instance_id, timeout=180)


        # The new wrapper around wait_for_all_public_ips as AWS is doing batch processing on large EC2 instance launches and
        # the code needs to wait for all the instances to be present and then poll and loop for all public ips to be present
        # the new functions are orchestarte_instance_launch_and_ip_polling and wait_for_instance_visiblilty (default timeout is
        # 180 seconds)
        instance_ips = orchestrate_instance_launch_and_ip_polling(exclude_instance_id=exclude_instance_id)
```



Finally, this tagging of the EC2 instances had to be added to module1 of the python package (all the other changes above
are from  module2):

This is only a small portion of the module:

```
       # Start EC2 instances
        try:
            response = my_ec2.run_instances(
                ImageId=image_id,
                InstanceType=instance_type,
                KeyName=key_name,
                SecurityGroupIds=['sg-0a1f89717193f7896'],
                # Specify SG explicitly. For now i am using the default SG so all authorize_security_group_ingress method callls
                # will be applied to the default security group.
                MinCount=int(min_count),
                MaxCount=int(max_count),
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'BatchID', 'Value': 'test-2025-08-13'},
                            {'Key': 'Patch', 'Value': '7c'}
                        ]
                    }
                ]

            )
            print("EC2 instances started:", response)
        except Exception as e:
            print("Error starting EC2 instances:", e)
            sys.exit(1)

        return response
```







## UPDATES: part 22: WATCHDOG_TIMEOUT adaptive mechanisms in hyper-scaling process benchmark testing.



### Introduction on AWS API contention during the control plane node setup:

The static WATCHDOG_TIMEOUT of 90 seconds is quite useful with high number of concurrent processes, because as the number of EC2
instances scale (assume for simplicity 1 thread per process case; but this supports full multi-threading) the probability of
API contention during EC2 node setup phase (in tomcat_install function) greatly increases.  For 512 concurrent processes there can be 
over 10 retry requests when AWS has to apply the security group rules to all of the nodes. In the gitlab console
logs these show up as RequestLimitExceeded counts with the current retry attempt number listed as well.

For example:

```
[Retry 2] RequestLimitExceeded. Retrying in 2.97s...

```

This is the second retry attempt due to the API request limit being reached during the EC2 node setup phase.
So this information is avaiable for each thread in the process and the peak Retry can be assessed real time during process/thread
execution, and this can be used to assess the degree of API contention that the process is experiencing in setting up its EC2 nodes
(chunk_size number of nodes).



Thus with respect to the API contention, assessing the real time max  number of RequestLimitExceeded retries for all the threads that
the process is working on is the best way to incorporate this metric into the overall adpative watchdog timeout at the per process
level.  


This is the current API exponential backoff code. This is a global level functon but as noted below it is called in the 
tomcat_worker() function(.


```
def retry_with_backoff(func, max_retries=15, base_delay=1, max_delay=10, *args, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for AWS API call.")
```


The current thread installation (data plane operation) is done in the instalL_tomcat()) function at the thread level. 

install_tomcat() is called by threaded_install() at the process level. threaded_install runs at the per process level.

threaded_install is called by run_test in the tomcat_worker function and is the ideal place to put much of the new adaptive watchdog
code.

The EC2 node setup phase (control plane) is done prior to the install_tomcat phase for obvious reasons.  
The EC2 node setup code is mostly in the tomcat_worker() function.  The call to run_test() in tomcat_worker() is done after all 
of the EC2 node setup code. So at this point the max  number of RequestLimitExceeded retries (a control plane metric) 
can be assessed and incorporated into the function that calculates the adaptive watchdog timer value (the function below named 
get_watchdog_timeout). The WATCHDOG_TIMEOUT is a data plan operation that is a timeout for the tomcat installation commands that
are sent to the node once the SSH connection is opened up.

This is the code which invokes the retry_with_backoff function above (there are several of these code blocks in
tomcat_worker() to exponentially back off during periods of API contention as the security rules are applied to the ndoes on the
backend after the authorize_security_group_ingress method is invoked:


```
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

```


### Justification for incorporating the API contention metric above into the data plane metric WATCHDOG_TIMEOUT:

The API contention above occurs during the contorl plane node setup phase of the execution.  The WATCHDOG_TIMEOUT is a 
data plane installation timeout value for installation commands sent to each node to install the tomcat9 on them.

The two are not related in a cause and effect manner but are correlated to each other.

Is API Contention a Proxy for EC2 Responsiveness?

What API Contention Measures
 - **RequestLimitExceeded** reflects AWS throttling the  API calls—typically during:
  - Security group updates
  - Instance launches
  - Describe operations

This is **control-plane contention**, not data-plane. This indicates that AWS is under pressure handling the  orchestration commands
and does not necessarily mean that the EC2 instances themselves are slow which would lead to slow installation times.


What API contention does not directly measure
- EC2 instance boot time
- SSH responsiveness
- Disk I/O or CPU performance inside the instance
- Package installation speed (`apt`, `systemctl`, etc.)

So API contention does not directly imply EC2 sluggishness


But There is  a Correlation


- When one launches 512 nodes, AWS’s backend is under load.
- That load can spill over into:
  - Delayed instance readiness
  - Slower network provisioning
  - I/O bottlenecks on shared infrastructure

So while API contention doesn’t cause slow installs, it **often co-occurs** with them—especially in burst scenarios.



Why Including Contention in `WATCHDOG_TIMEOUT` Still Makes Sense

Even if it’s not causally linked, it’s a **useful signal** for tuning:

- High contention → AWS is under stress → give more slack to watchdog
- Low contention → AWS is snappy → tighten watchdog to catch hangs faster

It’s a **defensive heuristic**, not a performance predictor.


#### Why execution times are not necessarily improved with the adaptive WATCHDOG_TIMEOUT


In short, parallelism masks individual install time variance, which is why total pipeline duration remains similar  across 
vastly different node counts. So even if install time per node creeps up under load, it’s amortized across the swarm.
And a 30 second increase in installation time across parallel node installations will not add much to the overall execution time
that is on the order of 10s of minutes.

Why Installation Time Might Not Matter in regards to the adaptive WATCHDOG_TIMEOUT

- **Parallel execution** means the slowest node defines the wall-clock time.
- If most nodes finish in 22s and a few take 50s, the tail latency matters—but only if it causes retries or watchdog triggers.
- Unless install time variance causes *failures*, it’s not a bottleneck.

Thus in the case of highly parallel operations,  **installation time is not a strong predictor of total execution time**, 
especially when the system is resilient to stragglers (which this system is designed to be).

#### The takeaway:

While API contention is a control-plane metric, it correlates with broader AWS infrastructure stress. Incorporating it into `
WATCHDOG_TIMEOUT` provides a defensive buffer against transient delays during node provisioning and setup. 
Although installation time per node may not scale linearly with node count due to parallelism, elevated contention increases the 
likelihood of stragglers and false watchdog triggers. The adaptive timeout mitigates this risk without compromising responsiveness.


#### Adaptive `WATCHDOG_TIMEOUT`: Strategic Justification

While execution time across node counts (e.g., 16 vs. 512) may remain roughly constant due to parallelism, the adaptive watchdog still
plays a critical role in system resilience and orchestration fidelity.


#### Why API Contention Still Matters

API contention—measured via `RequestLimitExceeded` retries—is a control-plane signal, not a direct measure of EC2 performance. 
However, it correlates with broader AWS infrastructure stress. High contention often co-occurs with:

- Delayed instance readiness  (control plane)
- Slower network provisioning (data plane) 
- Increased tail latency in node setup  (control plane)

Although installation time per node may not scale linearly with node count, elevated contention increases the likelihood of stragglers
and false watchdog triggers. Incorporating API contention into the timeout formula provides a defensive buffer against transient delays
without compromising responsiveness.


#### Why Adaptive Timeouts Are Still Valuable

Even if static watchdog data plane timeouts (e.g., 16s or 90s) yield similar total execution times, adaptive logic 
offers strategic advantages:

| **Benefit**                  | **Description**                                                                 |
|-----------------------------|---------------------------------------------------------------------------------
| Early Stall Detection     | Shorter timeouts catch transient hangs quickly, enabling retries before failure. 
| False Positive Reduction  | Longer timeouts reduce premature aborts caused by temporary delays.             
| Scalable Logic            | Timeout scales dynamically based on:                                            
| Node count                | More nodes → higher contention → longer timeout                                
| API contention            | Retry telemetry reflects AWS backend stress                                    
| Historical retry patterns | Allows tuning based on empirical data                                          
| Command type              | `apt` may need more slack than `systemctl`                                     

This adaptive strategy ensures that the watchdog remains responsive to real hangs while tolerating transient infrastructure 
noise—especially critical in large-scale parallel orchestration





### Preview of the get_watchdog_timeout function that calculates the adaptive WATCHDOG_TIMEOUT value


This is the new adative watchdog timer code that can be used to adaptively set the WATCHDOG_TIMEOUT in the current watchdog code
This is done at the per process level and applies to all the threads that the process will be working on.
This will be explained in more detail below in regards to the API contention max retry attempts

```
def get_watchdog_timeout(node_count, instance_type, peak_retry_attempts):
    base = 15
    scale = 0.15 if instance_type == "micro" else 0.1
    contention_penalty = min(30, peak_retry_attempts * 2)  # up to +30s
    return math.ceil(base + scale * node_count + contention_penalty)
```


The node_count is the total number of nodes deployed during the execution run

The instance_type is the instance type of the EC2 nodes (for example t2.micro)

The peak_rety_attempts will be calcualted per process based upon API contention with AWS (this will be done by a modified 
retry_with_backoff function)

The scale is a multiplier that is based upon the instance type (higher value for smaller vCPU instance type)
For initial testing with 512 nodes this will be set to 0.11 so that the watchdog timeout will remain at the original 90 second baseline

Use the math.ceil to round up.



### The WATCHDOG_TIMEOUT calculation will be done per process


The WATCHDOG_TIMEOUT will remain global but will be overwritten per process. Per process memory is not shared and this is ideal
for what is required here. 

An alternate solution is to produce a process level local variable for each watchdog timer and tag it with pid and perhaps a
timestamp or uuid, but unless deep forensic logging anaysis is required, this is not necessary.

With the global WATCHDOG_TIMEOUT being overwritten per process, there will be print gitlab console logs that will indicate the 
pid of the process and its unique value for the WATCHDOG_TIMEOUT and this is sufficent for what is required.

Based upon the API contention, the instance_type and the node_count, the WATCHDOG_TIMEOUT will be 
calculated per process. The only variable between processes will be the API contention metric as discussed below. This requires
the proper placement of the new code blocks relative to process vs. thread execution. This will be discussed further below.



### Requirement for threading lock on the max_retry_observed that is calculated in the retry_with_backoff:

#### Execution Context: Process vs. Thread

 `tomcat_worker` runs at the **process level**
- When `main` calls `pool.starmap(tomcat_worker_wrapper, args_list)`, it spawns multiple **OS-level processes**.
- Each process runs its own copy of `tomcat_worker_wrapper`, which then calls `tomcat_worker`.
- So the `for sg_id in ...` loop runs **inside a single process**, isolated from others.

AWS API calls inside `retry_with_backoff` are made **per process**
- Even if one runs 1 thread per process, each process still makes its own API calls to `authorize_security_group_ingress`.
- If one has 512 processes doing this concurrently, AWS sees 512 simultaneous API requests—hence the **RequestLimitExceeded** errors and high retry counts.

##### Requirement for the retry_lock (threading.Lock()) in the modified retry_with_backoff (code is below in next section)

If Multiple threads per process there is shared memory (unlike between processes)
- Inside each process, if one spawns multiple threads (via `ThreadPoolExecutor`), they all share the same `max_retry_observed`.
- Without a lock, two threads could try to update `max_retry_observed` at the same time, leading to race conditions or incorrect values

The `retry_lock` ensures atomic updates
- When a thread sees a retry count of 7, and another sees 9, need to make sure `max_retry_observed` ends up as 9.
- The `with retry_lock:` block guarantees that only one thread updates the counter at a time.





### Summary of placement of code blocks:


As mentioned above the ideal place for the new code that calculates the adaptive WATCHDOG_TIMEOUT is in run_test

There are 3 main code blocks that will be added (see next section below)

The first one is the retry_with_backoff modified function taht incorporates the calculation of the max_retry_observed over all of the
threads in the process (max_retry_observed will be calculated per process)

This is a global function at the top of the python module.

The call to the retry_with_backoff is still made in tomcat_worker using the for sg_id in set(security_group_ids): loops. These are
done early on in tomcat_worker() during the EC2 nodes setup phase. These are done prior to the call to threaded_install via the
run_test function.

At some point the run_test function is called in tomcat_worker(). By this time the max_retry_observed will have been calculated.
This metric is part of the calculation formula for the adaptive WATCHDOG_TIMEOUT value (per process)

In run_test the function get_watchdog_timeout is called (per process) to calculate the adaptive WATCHDOG_TIMEOUT value for the 
process

At the end of run_test the threaded_install function is called and this is where the ThreadPoolExecutor is invoked to actually
install tomcat on each of the EC2 nodes in the chunk_size for the process (by calling install_tomcat). The WATCHDOG_TIMEOUT
set earlier will be used for all of the install operations on all the threads in the process. It will have been optimized for 
the process based upon total number of nodes deployed in the execution, the node (instance) type and of course the API contention
that the process is experiencing (max_retry_observed).

These three code blocks are listed in the section below.






### These are some of the timeouts and ENV vars for the data plane watchdog area of the code:

```
WATCHDOG_TIMEOUT = 90
RETRY_LIMIT = 3
SLEEP_BETWEEN_ATTEMPTS = 5
STALL_RETRY_THRESHOLD = 2
```

### Code changes:

There are 3 main code blocks reqiured for this:


##### 1. A modified retry_with_backoff function that tracks the max number of retries for all the EC2 nodes (that will be threads) that the process is working on

```
import threading
import random
import time
import botocore.exceptions

# Per-process tracker for the highest retry attempt seen
max_retry_observed = 0
retry_lock       = threading.Lock()

def retry_with_backoff(func, max_retries=15, base_delay=1, max_delay=10, *args, **kwargs):
    """
    Wraps an AWS API call with exponential backoff on RequestLimitExceeded,
    and updates `max_retry_observed` to the highest retry index seen in this process.
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

```
The function sets max_retry_observed for each process.

Key points:

- **`max_retry_observed`** is a global in each worker process—multiprocessing isolation means each process has its own counter.
- **`retry_lock`** ensures two threads in the same process don’t stomp on each other when updating the counter.
- After the  EC2 setup calls complete, once can  read `max_retry_observed` and feed it into the  watchdog calculator function
get_watchdog_timeout
- This function as noted earlier, is called in tomcat_worker() as part of the EC2 node setup and this is PRIOR to when 
tomcat_worker calls run_test. Thus max_retry_observed will be set at this point
- Next, tomcat_worker will call run_test (see below). run_test  will first call get_watchdog_timeout to set the WATCHDOG_TIMEOUT 
and then the threaded_install will be called to install tomcat using this adative watchdog timeout during the installation process.
The code must be executed in this fashion.




#### 2. The global get_watchdog_timeout function that will be used to calcuate the adative WATCHDOG_TIMEOUT value for that process

```
# top of module
WATCHDOG_TIMEOUT = 90  # this will be overriden by each successive process
import threading

max_retry_observed = 0        # updated by modified retry_with_backoff (see above)
retry_lock = threading.Lock()

def get_watchdog_timeout(node_count, instance_type, peak_retry_attempts):
    base = 15
    scale = 0.15 if instance_type == "micro" else 0.1
    contention_penalty = min(30, peak_retry_attempts * 2)  # up to +30s
    return math.ceil(base + scale * node_count + contention_penalty)

```




#### 3. A modified run_test which is called by the tomcat_worker(). 

As noted above this is the ideal place to make the call to the get_watchdog_timeout to calcuate the WATCHDOG_TIMEOUT value for 
that process. The process will then go on to call threaded_install with this line at the end of run_test:    

    
```
result = func(*args, **kwargs) 
```


The threaded_install will install tomcat on the EC2 nodes using this specific WATCHDOG_TIMEOUT value. 

The WATCHDOG_TIMEOUT will continue to be global but will be rewritten for each process. The process memory is segregated and 
each process will have its own WATCHDOG_TIMEOUT value that is unique for the API contention that it is experiencing

Modified run_test:

```
def run_test(test_name, func, *args,
             min_sample_delay=50, max_sample_delay=250,
             sample_probability=0.1, **kwargs):

    # 1) decide whether to sample metrics
    delay = None
    if random.random() < sample_probability:
        delay = random.uniform(min_sample_delay, max_sample_delay)

    # 2) wrap in benchmark context
    with benchmark(test_name, sample_delay=delay):

        # ─── NEW BLOCK ───
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


        WATCHDOG_TIMEOUT = get_watchdog_timeout(
            node_count=node_count,
            instance_type=instance_type,
            peak_retry_attempts=max_retry_observed
        )

        print(f"[Dynamic Watchdog] [PID {os.getpid()}] "
              f"instance_type={instance_type}, node_count={node_count}, "
              f"max_retry={max_retry_observed} → WATCHDOG_TIMEOUT={WATCHDOG_TIMEOUT}s")



        # ─── actual call to threaded_install which returns thread_registry which is process_registry ───
        result = func(*args, **kwargs)
        return result
```





## UPDATES: part 21: Phase 2g: write-to-disk aggregator in main (working)

This involves another major overhaul. 



### Introduction:

See the troubleshooting in the last update below. The registry is being overwritten by each successive process that calls the
resurrection_montor. This requires a rewrit (patch 7c) in the resurrection_monitor as well as modifications to main(), tomcat_worker(), threaded_install(), install_tomcat(), run_test().

The initial interataion involved a few different approaches attempting to create an aggregate registry wihtout using write-to-disk. 
These all failed with the aggregate registry being reinitialized by each process. Process memory is not shared in multi-processing
environments.  A few other options were considered at this point like the following:

Multiprocessing.Manager dict:
  Use a shared manager dictionary to collect per-process results in memory, then dump once in `main()`.

But the IPC overhead and the debugging in cases where things go wrong would be too much in hyper-scaled processing.

The write-to-disk solution was the eventual solution.

Some of the early changes involved the following to resolved this overwritting issue:

A new patch 7c for the resurrection_monitor,  where a thread level registry is created,
and then at the process level the thread level registry is collected,  and then the process level registry is aggregated into a final
aggreagated_registry that has all the thread-level registry entries for all processes in the execution run.
This was a major rewrite of the code but failed even with the aggregation layer in the run_test and tomcat_worker and main().

However all the code at the process level can continued to be used. The only issue is switching over to write-to-disk for the final
aggregation of all the process level registries into on final aggregated registry (which will be used to compile status(tag) 
statistics on each thread (successful, failed, missing, total, etc). The main() will be used for all of this, but the 
resurrection_monitor will continue to be used to actually tag the threads with a status at the process level. It now fully supports
multi-threaded processes. Two helper functions were also created aggregate_process_registries and summarize_registry. These helper functions along with the changes to threaded_install and install_tomcat can still be used.

A further background on the resurrection_monitor_patch7c
This is a major rewrite of the code. The execution is multi-processed and mult-threaded (installations, and python modules, etc), but
the registry tracking of the threads along with their "status" or tag needs to be completely overhauled to support the multiple threadsper process where each thread is a dedicated SSH connection to an EC2 node. 
So even though the execution upper level main and process orchestration logging has always been multi-processed and multi-threaded, the
tagging and the logging and stats for it  had to be completely overhauled to support multi-threaded processes

Once this is in place the resurrection logging at the process level will work as well as the tagging and this can all be aggregated 
using write-to-disk at the main() level.
Most of the artifact logging will be moved to the main() and out of the resurrection_monitor (Except for a few process level logs
that will be json files of the resurrectino candidates per process and ghost threads per process), but the aggregate for the 
resurrection candidates and ghosts will be in main(). These aggregates will be used for phase3 of the project to resurrect the 
threads.

All arficact logs will be piped into the gitlab pipeline (/logs) from the mounted volume in the python container (/aws_EC2/logs)
and the artifact logging that is piped into the gitlab pipeline (/logs) will work for in-depth forensics on the thread status. 
The process_registry will continue to be used at the per process level (multi-threading supported) internally, and these will
be written to disk (/aws_EC2/logs) at the process level.
main()  will now aggregate all the process_registry that are on disk as json into one registry so that it can be processed for
statistics (success, failed, mssing, total) and also piped to the gitlab pipeline artifact logs.


### artifact logs published to gitlab pipeline

The artifact logs are listed below. Each run of the gitlab pipeline will produce these logs. Most of these logs are produced in
main() now, with the process level registry logs being produced in resurrection_monitor_patch7c, and the main orchestration logging
produced throughout the python module.


```
artifacts:
    paths:
      - logs/
      - logs/main_*.log  # top elve orchestration level stats for entire execution
      - logs/benchmark_*.log  # process level orchestration level stats logs 
      - logs/benchmark_combined.log  # this is the orchestration level logging of all the benchmark_*.logs (process level stats). This is created post execution in gitlab-ci.yml (seea above)

      - logs/benchmark_combined_runtime.log  # this is the python run time created benchmark_combined stats log created from the benchmark_*.log pid logs that are created during run time.  
      
      - logs/benchmark_ips_artifact.log  # this is the GOLD standard by which to compare the runtime registires to for missing, failed, successful and total (in addtion to scanning the tags/status)

      - logs/total_registry_ips_artifact.log  # stats created from the final_aggregate_execution_run_registry.json registry. THese are the actual registry entries, not stats. Same for the next 3 logs as well.
      - logs/missing_registry_ips_artifact.log
      - logs/successful_registry_ips_artifact.log
      - logs/failed_registry_ips_artifact.log
      
      - logs/patch7_summary_*.log # this is for the per process logging in resurrection_monitor_patch7c. This is completely separate from the orchestration level logging and this is used for forensics and debugging.
      
        # these are process level logs from the resurrection_montior_patch7c(). These are actual registry entries for resurrection candidates for phase3 implementation. Ghosts are missing when compared to GOLD standard and do not have standard failure tags  
      - logs/resurrection_candidates_registry_*.json
      - logs/resurrection_ghost_missing_*.json
     
      # resurrection_monitor pid based snapshot for all registry values. This has been replaced with final_aggregate_execution_run_registry.json
      #- logs/resurrection_process_registry_snapshot_*.json
      
      # write-to-disk aggregator json files. The log files above are derived from these. This has all registry values for the
      # entire execution run. This replaces the snapshot json log above that was formerly done in resurrection_monitor
      # This log below is done in main()
      - logs/final_aggregate_execution_run_registry.json
      
        # per process registry logs from tomcat_worker(). These are used to create the final_registry and summary and these are then used to create the aggregate registry for the execution run : logs/final_aggregate_execution_run_registry.json
      - logs/process_registry_*.json  

```


By design:

- Per-PID dumps only when there’s real content (failures or ghosts).  
- A single aggregate logs always written—showing blanks to signal “all clear.”  

This blend gives just the right visibility at scale: lightweight per-process alerts when things go sideways plus a reliable high-level summary every run. 

Advantages:
- No wasted I/O on all-success flows.
- Immediate forensic breadcrumbs on the rare failures.
- Consistent aggregate artifacts for your Phase 3 pipeline.
- Frugal publishing of the process logs: if they are blank then they will not be published. With hyper-scaling this will help a lot.





Once this artifact logging is  in place the Phase 3 can be rolled out (whereby threads are resurrected) and after that Phase 4 ML (machine learning) to
adpatively modulate orchestration to minimize the use of the Phase 3 resurrection thread healing and optimize the orchestation of
the process handling and thread handling. 

Each step along the way the process level will continue to be scaled up. (currently at 512 processes with 1 thread per process, and
the failures have been root cause defined).
 





### Review of function flow

The function flow is instrumental in understanding the design changes in the functions listed below.



main() calls tomcat_worker_wrapper in the multi-processing context.  

```
##### CORE CALL TO THE WORKER THREADS tomcat_worker_wrapper. Wrapped for the process level logging!! ####
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
```


tomcat_worker_wrapper() calls tomcat_worker()

tomcat_worker_wrapper() is required for the main and process orchestration level logging




tomcat_worker() calls threaded_install() at the process level through the run_test() function

```
process_registry = run_test("Tomcat Installation Threaded", threaded_install)
```

run_test calls threaded_install and threaded_install aggregates the registry_entry for each thread in the process
and returns this as thread_registry for each process that calls it. 


the return in threaded_install (thread_registry) is assigned to the process_registry which is the process level registry for all the 
threads in the process (as noted the process registry is exported as an artifact in the gitlab artifact logs)



The threaded_install() at the process level, calls the install_tomcat() function through the ThreadPoolExecutor
The ThreadPoolExecutor works on all the threads in the process using multi-threading by calling the install_tomcat per thread

```
with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_info]
```



install_tomcat() works at the individual thread level (per EC2 instance) and each thread is represented by registry_entry
This is a single registry entry that the calling functino (threaded_install) aggregates at the process level when there are
multiple threads per process.

The challenge here is to simulatenously do main() and process orchestration logging
Also process based logging (done in resurrection_monitor_patch7c)
And also thread level registry maintenance, logging and tracking for statistics and phase3 thread resurrection.
The logging is the most difficult aspect of the project. 





### thread level, process level and the aggregator level registries:


The registry_entry from install_tomcat() is returned to threaded_install() and threaded_install collects the registry_entry for
each thread (multiple threads per process) into thread_registry



threaded_install() returns the thread_registry (has all the threads in a process) to the calling function run_test() in tomcat_worker()
This is the "result" used in the run_test function 

```
result = func(*args, **kwargs)
```

run_test and tomcat_worker would seem like an ideal place to aggregate the process level registries, but because python multi-processes do not share
memory, this cannot work.  By the time an "aggregate" registry is passed up to main() it has been rewritten by each successsive 
process. There are a few solutions to this and I am using write-to-disk.
If the process level registry is written to disk (a docker container /aws_EC2/logs mounted volume), this can later be combined
in main() as an aggregate repository which is ideal for stats, and resurrection based upon the registry thread status(tag) (Phase 3)


What still can be done is the function call to resurrection_monitor_patch7c in tomcat_worker for each process_registry 

```
process_registry = run_test("Tomcat Installation Threaded", threaded_install)
```
This process_registry is assigned as above in tomcat_worker, and tomcat_worker can then call resurrection_monitor_patch7c
for each process registry for tagging (status) classification, etc.  resurrection monitor no longer exports artifacts
(that is done in main()), except for one log file benchmark_ips_artifact.log which is the GOLD standard that the 
runtime aggregate registry will be compared to when collating and creating stats.

In addition, resurrection_monitor will still be used to create the following 2 process level json registry files for 
process level resurrection registry candidates and ghost threads.  But an aggregate will also be created in main() as well.



```
# registry threads with some sort of failure tag/status
log_path = os.path.join(log_dir, f"resurrection_candidates_registry_{pid}.json")

# registry threads that are missing from the list of total ips in the exeuction run (very rare because these are unclassified falures)
ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_missing_{pid}.json")

```


The aggregated registry will be created in main() along with the successful, failed, missing and total registry log files 

So there are 3 levesl of registries, registry_entry at thread level, process_registry at the process level and then the 
final aggregated registry for all processes and threads in the execution run 
This final registry is logs/final_aggregate_execution_run_registry.json referred to above in the section on artifacts and logs.





### summary of function flow with write-to-disk (WIP):


1. **main()**  
   - Splits your EC2 tasks into `chunks` (size chunk_size)
   - Builds `args_list` of `(chunk, security_group_ids, max_workers)`
   - max_workers is the number of threads (eventually used by ThreadPoolExecutor_ 
   - Calls `multiprocessing.Pool(processes=desired_count)` and `pool.starmap(tomcat_worker_wrapper, args_list)`.
   - desired_count is the initial processes used to process the chunks. For example,if 525 EC2 instances and max_workers = 1,
     and desired_count = 500, there will be an inital wave of 500 processes of 1 thread each to process the first 500 EC2 instances,
     and then as these processes are freed, another 25 pooled processes of 1 thread each to process the last 25 EC instances in a 
     second wave
   - Note that for performance reasons max_workers should always be greater than or equal chunk_size. If max_workers is less than
     chunk_size the performance will degrade.

2. **tomcat_worker_wrapper()**  
   - Runs `setup_logging()` so each pooled task gets its own fresh log.  (this is orchestration layer logging)
   - Delegates to `tomcat_worker(instance_info, security_group_ids, max_workers)`.

3. **tomcat_worker()**  
   - Calls `run_test("Tomcat Installation Threaded", threaded_install)`, which:  
     - Enters the `benchmark` context (sampling CPU/swap).  
     - Executes `threaded_install()`.

4. **threaded_install()**  
   - Uses `ThreadPoolExecutor(max_workers)` to spin up threads.  (each process is multi-threaded if requrired)
   - Each thread runs `install_tomcat(ip, private_ip, instance_id)`.  
   - Collects per-thread results into `thread_registry` keyed by `thread_uuid`.  
   - Returns that `thread_registry` back to `tomcat_worker` as `process_registry`.

5. **Disk Handoff in tomcat_worker()**  
   - After obtaining `process_registry`, it writes  
     ```
     /aws_EC2/logs/process_registry_<pid>_<uuid>.json
     ```
   - Calls `resurrection_monitor_patch7c(process_registry)` and snapshots and tags the threads with status, etc.
     The resurrection_monitor_patch7c also creates a process level resurrection candidate json registry listing file as well
     as a ghost json registry listing file of threads that are missing when compared to the GOLD standard of what should be 
     present (benchmark_ips_artifact.log)

6. **Final Aggregation in main()**  
   - In `finally:` of the Pool block, loads every `/aws_EC2/logs/process_registry_*.json` into `registries`.  
   - Flattens with `aggregate_process_registries(registries)` and summarizes with `summarize_registry(final_registry)`.  
   - Writes the merged `/aws_EC2/logs/final_aggregate_execution_run_registry.json` and prints the tag counts based on 
     summarize_registry.   

     - Note that the actual tagging (the status) of each thread is done by resurrection_monitor_patch7c at
     the process level as well as throughout the module for various failure scenarios. The full code changes in this function are in
     the next sections below

     - Note also that the actual ips that are successful, failed, missed and total will be in separate logs also created in main(). The
     full code changes in main() are give in the the sections further below.

The helper functions and a paritial of main() are below in the context of the function descriptions above.
 
The FULL changes to the larger functions mentioned above are given in the next few sections below.

Note that the summary status tags below may change and there may be additonal ones added as scaling is increased and new failure
consitions surface


#### parital of main() in the context of the description above (FULL code changes are in the next main section below)


```
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


```




#### aggreagate_process_registries()

```
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
```



#### summarize_registry()

```
def summarize_registry(final_registry):
    summary = {
        "total": len(final_registry),
        "install_success": 0,
        "gatekeeper_resurrect": 0,
        "watchdog_timeout": 0,
        "ssh_initiated_failed": 0,   # placeholder for Patch 8 later
        "ssh_retry_failed": 0,       # placeholder for patch 8 later
        "no_tags": 0,
    }
```



### Full code changes to the major functions involved in migation to write-to-disk using the existing process level infra:

NOTE: The code commented out in several functions to revert the run_test and global aggregator code is marked in the module as:

--- COMMENTED OUT FOR DISK-HANDOFF write-to-disk WORKFLOW ---



NOTE: At the process level the log and json files will not be produced if there is no data in them.  
Conversely,  at the aggregate level (this write-to-disk aggregation code), blank files will be produced.
The reasoning is that blank aggregate level artifact files will not produce a lot of overhead during hyper-scaling of
processes, whereas blank process level artifcat files would have created an enormous amount of unecessary overhead
during process hyper-scaling.



##### resurrection_monitor_patch7c() This is a work in progress. Patch7d and Patch8  will add more changes to this.


The main changes to the resurrection_monitor_patch7c are the commenting out of the artifact log files below. These
have been migrated to the main() level rather than being assembled at the process level. In patch7d and patch8 of the
resurrectino_monitor, the process level logging for resurrection candidates and ghost threads will be added, but the
log files below that are commented out are not necessary at the process level. All of these will be generated in main()
at the aggregate level.


```
## coment out the total, missing and the successful and the failed as these are done in main() now at the aggregated and not 
## the process level. benchmark_ips_artifact.log is the GOLD standard used by main(). So keep this one. Remove the other ones 
## from here.

            #if not total_registry_ips:
            #    patch7_logger.info("[Patch7] WARNING: total_registry_ips is empty — skipping artifact.")   
            #else:
            #     safe_artifact_dump("total_registry_ips", total_registry_ips)

            if not benchmark_ips:
                patch7_logger.info("[Patch7] WARNING: benchmark_ips is empty — skipping artifact.")
            else:
                safe_artifact_dump("benchmark_ips", benchmark_ips)

            #if not missing_registry_ips:
            #    patch7_logger.info("[Patch7] WARNING: missing_registry_ips is empty — skipping artifact.")
            #else:
            #    safe_artifact_dump("missing_registry_ips", missing_registry_ips)

            #if not successful_registry_ips:
            #    patch7_logger.info("[Patch7] WARNING: successful_registry_ips is empty — skipping artifact.")
            #else:
            #    safe_artifact_dump("successful_registry_ips", successful_registry_ips)

            #if not failed_registry_ips:
            #    patch7_logger.info("[Patch7] WARNING: failed_registry_ips is empty — skipping artifact.")
            #else:
            #    safe_artifact_dump("failed_registry_ips", failed_registry_ips)




#            dump_set_to_artifact("total_registry_ips", total_registry_ips)
#            dump_set_to_artifact("benchmark_ips", benchmark_ips)
#            dump_set_to_artifact("missing_registry_ips", missing_registry_ips)
#            dump_set_to_artifact("successful_registry_ips", successful_registry_ips)
#            dump_set_to_artifact("failed_registry_ips", failed_registry_ips)
```


The following functions are listed from top (main()) level down to the process level functions and then to the thread level
function (install_tomcat())

It is important to differentiate between process level, thread level and the aggregate level functions when designing the
write-to-disk aggregator code (mostly residing in main())

The design is apparent when looking at the code from the top down as follows:






##### main() This is where most of the new aggregation code is now:

Note that all of the log and json artifact files generated in main are at the aggregate level (the total execution 
set of IPs). The process level artifacts will be created in a resurrection_monitor_patch7d at a later time.


```

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

        # 5. Load the benchmark IP list (gold standard to compare to). This is created in resurrection_monitor_patch7c() function
        benchmark_ips = set()
        with open("/aws_EC2/logs/benchmark_ips_artifact.log") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    benchmark_ips.add(ip)

        # 6. Build IP sets from final_registry statuses (final registry is the aggregate runtime list of all the threads with ip addresses)
        # Get the success_ips from the tag(status), get failed as total - success and get missing as benchmark_ips(gold) - total_ips
        total_ips   = {e["public_ip"] for e in final_registry.values()}
        success_ips = {
            e["public_ip"]
            for e in final_registry.values()
            if e.get("status") == "install_success"
        }
        failed_ips  = total_ips - success_ips
        missing_ips = benchmark_ips - total_ips

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
```





##### tomcat_worker()

The call to tomcat_woker is done from tomcat_worker_wrapper which is called directly from main()

tomcat_worker_wrapper is used for upper level orchestration logging via the setup_logging() helper function 
No changes were required in the wrapper itself.

tomcat_worker has the "process_registry" which is created by calling threaded_install by using the run_test helper
function

```
## threaded_install now returns the thread_registry (list of all IPs in the process as a process registry)
    ## Assign this thread_registry the name process_registry. This will later be passed to the new resurrection_monitor_patch7c
    ## for collating and tag processing
    ## NOTE that run_test needs to be slightly modified to return the thread_registry from threaded_install so that it can be
    ## assigned to the process_registry
    process_registry = run_test("Tomcat Installation Threaded", threaded_install)
```


Once the process_registry is obtained for the current process that is running tomcat_worker, it needs to be written
to disk. This is because memory is NOT shared between processes, so the state needs to be saved as a discrete 
`process_registry_{pid}_{tag}.json file`, that is later assembled at the aggregate level in main() (see above; step 1)


```
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
```




##### run_test()

The call to run_test is done within tomcat_worker() (see above)
run_test is used to call threaded_install which returns thread_registry which is the process_registry for the current process

No changes were required in run_test for the write-to-disk.

The threaded_install function is called through the `*args` in the return at the end of run_test():

```
result = func(*args, **kwargs)
```





##### threaded_install()

The call to threaded_install() is from tomcat_worker via the run_test helper function.  threaded_install is a process level 
function and returns thread_registry which is assigned to "process_registry" in tomcat worker


The threaded_install calls install_tomcat through the ThreadPoolExecutor a multi-threading thread level executor of the tomcat
installation for all the threads in the process. Given that the process_registry is written to disk in the threaded_install
function (see above), no changes were required for the write-to-disk aggregator in threaded_install

```
       with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_info]
```

NOTE for future patches to resurrection_monitor that the registry should always be indexed by the thread_uuid:

```
# Store in registry keyed by IP or UUID. This keeps them uniqe regardless of pid reuse.
                # For multi-threaded multi-processed registry entries keying by thread_uuid is best.
                # thre thread_registry will be built up with all thread registry entries for per process and returned to the
                # calling function of threaded_install which is tomcat worker. Tomcat_worker will assign this to process_registry
                # retgistry_entry is returned from install_tomcat to this function, threaded_install
                thread_registry[thread_uuid] = registry_entry
```

threaded_install will return thread_registry which is effectively process_registry to the calling function run_test which 
returns this registry list to tomcat_worker so that these process level registries can be aggregated in main()






##### install_tomcat()

The call to install_tomcat() is done from threaded_install() via the ThreadPoolExceutor. install_tomcat() is a thread level
functon and returns registry_entry, a single thread registry entry, to threaded_install, a process level function that 
collects all of the registry_entry from all the threads in the process and then returns them to tomcat_worker. This process
level registry is "process_registry". 

install_tomcat as a thread level function does not require any changes for the write-to-disk aggregator.


In summary, the code changes for the write-to-disk aggregator are at the process and top aggregation level. As such the 
lower level functions did ot require any changes and  most of the changes were in main() and tomcat_worker() as detailed
above.








## UPDATES: part 20: Phase2f: Patche 7c in resurrection_monitor, aggregator in run_test() and global with tomcat_worker() (neither one resolved the issue)

The problem is detailed below. This involved changes to the run_test, threaded_install, install_tomcat, and 
resurrection_monitor_patch7c as well as tomcat_worker.
Two helper functions were also created aggregate_process_registries and summarize_registry. These helper functions along with the 
chaanges to threaded_install and install_tomcat can still be used.

There were two fixes that were tried, one, an aggregator in run_test() and the other using a global list at the top of the module and
then using this in tomcat_worker() to save each process registry, and then use the 2 helper functions in main()  to flatten and collect stats on
the global registry.

The fixes did not resolve the issue (see UPDATES part 21 above for the proper fix (write-to-disk)
The aggregator in run_test did not resolve the issue
The attempt to use a globla all_process_registries did not work either
These parts of the code have been commented out.

tomcat_worker and main() will have to be edited to support write-to-disk (see above)
the process_registry json produced in tomcat_worker will be used for the migration to write-to-disk in main()



### Detail on patch 7b to 7c migration requirements (from the last update):

Resurrection registry snapshots are being overwritten per process, rather than accumulated across processes
That explains why `successful_registry_ips` only shows one IP per run — the last IP of the last process to complete. (In this
simple test there was only 1 thread per process hence 1 IP being processed per process)

#### Root Cause  

- install_tomcat correctly tags each thread-level IP called registry_entry
- threaded_install correctly collects the thread-level registry into a process-level registry called thread_registry
- run_test is called by tomcat_worker and run_test calls threaded_install. The problem is that for each process, the process_registry
is being overwritten by the last process to run.
- the resurrection_monitor only has the process_registry which does not contain the full list of threads in the execution run and thus 
the files and logs that it creates are not correct
- Even though each thread logs its IP, the final snapshot only contains only the thread IPs of the last process to run
- an aggregator needs to be created in the run_test so that each call to threaded_install (thread_registry) at the process level is 
aggregated into an aggregate_registry that has all the IPs (threads) for the entire execution run across all processes
- the process_registry has to be deprecated for the aggregate_registry (even though the registries are still collected at the process
level internally)
- once the aggregate_registry is created by run_test the return of aggregate_registry to tomcat_worker() is then used as input into 
the resurrection_monitor
- At this point the resurrection_monitor has the full set of IPs for all threads in the execution run (across all proceses) and the logs
and artifacts will be created correctly from this registry



#### High level summary of patch 7c

- Per-thread registries to capture granular tagging inside `install_tomcat()`.
- Per-process collection of the threads in a process for a process level registry in threaded_install()
- Aggregation of the process level registries in run_test (which calls threaded_install() per process)
- Per-process roll-up (within `run_test`) using an aggregator that avoids overwriting earlier thread and process registry data.
- From the aggregate_registry, resurrection monitor then writes clean, aggregated logs, json files and artifacts (to gitlab
pipeline)




### changes to run_test()  (this did not work and has been removed)

The aggregator is added to run_test(). This is the ideal place given the software design function flow above.

```
## This needs to be slightly modified for the patch7c to return the thread_registry from threaded_install
## run test is invoked with func threaded_install and this now returns the thread_registry which will later 
## be assigned proces_registry to be consumed by resurrection_monitor_patch7c

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):
    delay = None
    if random.random() < sample_probability:
        delay = random.uniform(min_sample_delay, max_sample_delay)

    with benchmark(test_name, sample_delay=delay):
        result = func(*args, **kwargs)
        #func(*args, **kwargs)

    #return result


    # Aggregation logic (only if result is a list of thread_registry dicts)
    aggregate_registry = {}
    if isinstance(result, list):  # assuming threaded_install returns a list of thread_registry dicts
        print("[TRACE][run_test] Entered run_test()")
        for thread_registry in result:
            print(f"[TRACE][run_test] thread_registry keys: {list(thread_registry.keys())}")
            print(f"[TRACE][run_test] aggregate_registry BEFORE update: {len(aggregate_registry)}")
            aggregate_registry.update(thread_registry)
            print(f"[TRACE][run_test] aggregate_registry AFTER update: {len(aggregate_registry)}")

        # ✅ Aggregation trace
        print(f"[TRACE][run_test] Aggregate registry has {len(aggregate_registry)} entries")
        for uuid, entry in aggregate_registry.items():
            if entry.get("status") == "install_success":
                print(f"[TRACE] UUID {uuid} | IP: {entry.get('public_ip')} ✅")

        # 🧪 Forensic validator: compare aggregate_registry IPs to benchmark_ips_artifact.log
        try:
            with open("logs/benchmark_ips_artifact.log") as f:
                benchmark_ips = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            benchmark_ips = set()
            print("[WARN] benchmark_ips_artifact.log not found")
        aggregated_ips = {
            entry.get("public_ip")
            for entry in aggregate_registry.values()
            if entry.get("public_ip") is not None
        }

        missing_ips = benchmark_ips - aggregated_ips
        extra_ips = aggregated_ips - benchmark_ips

        print(f"[TRACE] Benchmark IPs: {len(benchmark_ips)} | Aggregated IPs: {len(aggregated_ips)}")
        print(f"[TRACE] Missing IPs in aggregate: {missing_ips}")
        print(f"[TRACE] Extra IPs not in benchmark: {extra_ips}")

    return result
```

### changes to tomcat_worker() to aggregate the process level registries to global all_process_registries,  and then main() to use 2 helper functions (this did not work)



The helper functions can still be used with the write-to-disk solution

tomcat_worker() code:

```
#
#    import copy
#    all_process_registries.append(copy.deepcopy(process_registry))
#
```



main() code is below:

```
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
```







## UPDATES: part 19: Phase2e: Patches 7a and 7b in resurrection_monitor


### Introduction:

Now that the elusive ghosts have been identified (early SSH connect aborted silent failures), we can create patch7 to report and track
these threads in the registry and also patch8 to add to the SSH connect code tagging (ssh_initialized_failed and ssh_retry_failed)
for silient SSH early connect fails (current ghost threads) and for SSH connections that fail all 5 retries of the outer loop.
Just as a review: there is an outer SSH connect loop (5 retries) and a loop inside that for 3 install tomcat9 retries and then inside
each of those a max of 2 watchdog timeout retries.  We are working with the outer loop here.  With these changes the SSH connect
fails will show up in total_registry_ips as well as failed_registry_ips where total_registry_ips = successful_registry_ips +
failed_registry_ips.

The objective here is to populate these two json log files



```
def resurrection_monitor(log_dir="/aws_EC2/logs"):
    pid = multiprocessing.current_process().pid
## These are the resurrection_registry patch 1-5 logs
    log_path = os.path.join(log_dir, f"resurrection_registry_log_{pid}.json")
## These are teh resurrection ghost patch 6 logs
    ghost_log_path = os.path.join(log_dir, f"resurrection_ghost_log_{pid}.json")


### ✅ `resurrection_registry_log_{pid}.json`
- Final tagged state of every IP thread, post-Patch1 through Patch8
- Should reflect **one definitive tag per IP**, such as:
  - `install_success`
  - `ssh_retry_failure`
  - `watchdog_threshold_exceeded`
  - `ssh_initiated_timeout`
- **Phase 3 logic:**
  - Filter out entries with `install_success`
  - Queue up everything else for resurrection attempts
  - Resurrection scope now covers all failure modes — even the `Patch8`-tagged SSH ghosts

---

### 👻 `resurrection_ghost_log_{pid}.json`
- Reserved for threads that *never* made it into the registry log
  - e.g. `missing_registry_ips ≠ 0`
  - Or benchmark activity exists, but registry is blank (rare edge case post-Patch8)
- It functions like a **fallback net** — the "phantoms" that bypassed the tagging engine entirely
- Should be nearly empty now, and you can toggle it off unless you're chasing anomalies

So to summarize: Patch8 plugs SSH ghost leaks by tagging them into the registry; Phase 3 then does the actual resurrection sweep — rebooting, retrying, or reassigning any IP whose final registry state is marked as anything *but* success. Ghost log becomes the anomaly detector and noting more for extreme edge cases.


```

The list of artifacts sent to the gilab pipeline are below once everything in patch7b is working correctly:


From the .gitlab-ci.yml file these are pulled from a mounted volume on the python docker container, into the /logs 
artifacts directory of the gitlab pipeline for this project during the deploy stage: 


```
  artifacts:
    paths:
      - logs/
      - logs/benchmark_combined.log
      - logs/benchmark_combined_runtime.log
      - logs/total_registry_ips_artifact.log
      - logs/benchmark_ips_artifact.log
      - logs/missing_registry_ips_artifact.log
      - logs/successful_registry_ips_artifact.log
      - logs/failed_registry_ips_artifact.log
      - logs/patch7_summary_*.log
      - logs/resurrection_registry_log_*.json
      - logs/resurrection_ghost_log_*.json

```




### Patch 7a


The problem with this code was log leakage into the benchmark process level logging and the main orchestrations logging
The problem was so signficant that this patch 7a had to be completely rewritten to compleley segregate that logging from the
patch7 level thread/resurrection logging. This resulted in patch 7b. Patch 7b has all the comnmented code that points out what
needed to be done to resolve this issue, namely file based logging to avoid the stdout interference that was inherent in the 
patch 7a code below.   The patch 7b code uses a dedicated patch7_logger per pid and is working very well now.


```
######### ORIGINAL PATCH 7a ########################
#
#
#        # Inside resurrection_monitor, just before Patch7 block
#        # Initialize the logger for the patch7 below
#        patch7_logger = logging.getLogger("patch7")
#        patch7_logger.setLevel(logging.INFO)
#
#        if not patch7_logger.hasHandlers():  # Avoid duplicate handlers
#            #handler = logging.StreamHandler()
#            handler = logging.StreamHandler(stream=sys.stdout)  # Ensure we hit stdout
#            formatter = logging.Formatter('[Patch7] %(message)s')
#            handler.setFormatter(formatter)
#            patch7_logger.addHandler(handler)
#
#        # ------- Patch7 Setup: Extract and Compare IP Sets(Replace original patch6 with this entire block; this has patch6) -------
#
#        # Replace logger.info(...) with patch7_logger.info(...)
#        patch7_logger.info("Patch7 Summary — etc.")
#
#        # Step 1: Combine runtime benchmark logs
#        def combine_benchmark_logs_runtime(log_dir):
#            combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
#            with open(combined_path, "w") as outfile:
#                for fname in sorted(os.listdir(log_dir)):
#                    if fname.startswith("benchmark_") and fname.endswith(".log"):
#                        path = os.path.join(log_dir, fname)
#                        try:
#                            with open(path, "r") as infile:
#                                outfile.write(f"===== {fname} =====\n")
#                                outfile.write(infile.read() + "\n")
#                        except Exception as e:
#                            print(f"[Patch7] Skipped {fname}: {e}")
#            print(f"[Patch7] Combined runtime log written to: {combined_path}")
#            return combined_path
#
#        # Step 2: Create benchmark_path variable using runtime combiner
#        benchmark_path = combine_benchmark_logs_runtime(log_dir)
#
#        # Step 3: Begin Patch7 logic
#        try:
#            with open(benchmark_path, "r") as f:
#                benchmark_ips = {
#                    match.group(1)
#                    for line in f
#                    if (match := re.search(r"Public IP:\s+(\d{1,3}(?:\.\d{1,3}){3})", line))
#                }
#
#
#        # Step 4: Continue with the Patch7 logic
#
#            total_registry_ips = set(resurrection_registry.keys())
#
#            successful_registry_ips = {
#                ip for ip, entry in resurrection_registry.items()
#                if (
#                    entry.get("install_log") and "Installation completed" in entry["install_log"]
#                    and entry.get("watchdog_retries", 0) <= 2
#                )
#            }
#
#            failed_registry_ips = total_registry_ips - successful_registry_ips
#            missing_registry_ips = benchmark_ips - total_registry_ips
#
#            # ------- Dump All Sets to Artifact Log Files -------
#            def dump_set_to_artifact(name, ip_set):
#                path = os.path.join(log_dir, f"{name}_artifact.log")
#                with open(path, "w") as f:
#                    for ip in sorted(ip_set):
#                        f.write(ip + "\n")
#                print(f"[Artifact Dump] {name}: {len(ip_set)} IPs dumped to {path}")
#
#            dump_set_to_artifact("total_registry_ips", total_registry_ips)
#            dump_set_to_artifact("benchmark_ips", benchmark_ips)
#            dump_set_to_artifact("missing_registry_ips", missing_registry_ips)
#            dump_set_to_artifact("successful_registry_ips", successful_registry_ips)
#            dump_set_to_artifact("failed_registry_ips", failed_registry_ips)
#
#            # ------- Patch6 Ghost Flagging -------
#            for ip in missing_registry_ips:
#                flagged[ip] = {
#                    "status": "ghost_missing_registry",
#                    "ghost_reason": "no resurrection registry entry",
#                    "pid": pid,
#                    "timestamp": time.time()
#                }
#                log_debug(f"[{timestamp()}] Ghost flagged (missing registry): {ip}")
#
#
#            patch7_logger.info("🧪 Patch7 reached summary block execution.")
# 
#            # ------- Patch7 Summary using patch7_logger -------
#            patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
#            patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
#            patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
#            patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
#            patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
#            patch7_logger.info(f"Composite alignment passed? {len(missing_registry_ips) + len(total_registry_ips) == len(benchmark_ips)}")
#
#
#
#        except Exception as e:
#            log_debug(f"[{timestamp()}] Patch7 failure: {e}")
#        
#

```

### Patch 7b

Recap: The problem with patch 7a code was log leakage into the benchmark process level logging and the main orchestrations logging
The problem was so signficant that patch 7a had to be completely rewritten to compleley segregate that logging from the
patch7 level thread/resurrection logging. This resulted in patch 7b. Patch 7b has all the comnmented code that points out what
needed to be done to resolve this issue, namely file based logging to avoid the stdout interference that was inherent in the
patch 7a code below and using patch7_logger per pid.   The patch 7b code uses a dedicated patch7_logger per pid and is working very well now.



```
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

        summary_log_path = os.path.join(log_dir, f"patch7_summary_{pid}.log")
        summary_handler = logging.FileHandler(summary_log_path)
        summary_formatter = logging.Formatter('[Patch7] %(message)s')
        summary_handler.setFormatter(summary_formatter)
        patch7_logger.addHandler(summary_handler)

        patch7_logger.info("Patch7 Summary — initialized")

        # ------- Step 1: Combine runtime benchmark logs -------
        #merged contents from all `benchmark_*.log` PID logs that were created at runtime
        def combine_benchmark_logs_runtime(log_dir):
            combined_path = os.path.join(log_dir, "benchmark_combined_runtime.log")
            with open(combined_path, "w") as outfile:
                for fname in sorted(os.listdir(log_dir)):
                    #if fname.startswith("benchmark_") and fname.endswith(".log"):
                    # Make sure only combining NON aggregated benchmark logs, i.e. only benchmark pid logs    
                     
                    if (
                        fname.startswith("benchmark_") 
                        and fname.endswith(".log") 
                        and "combined" not in fname
                    ):

                        path = os.path.join(log_dir, fname)
                        try:
                            with open(path, "r") as infile:
                                outfile.write(f"===== {fname} =====\n")
                                outfile.write(infile.read() + "\n")
                        except Exception as e:
                            patch7_logger.info(f"Skipped {fname}: {e}")
            patch7_logger.info(f"Combined runtime log written to: {combined_path}")
            return combined_path



        # ------- Step 2:Create benchmark_path variable using runtime combiner -------
        # The benchmark_path for example: /aws_EC2/logs/benchmark_combined_runtime.log
        benchmark_path = combine_benchmark_logs_runtime(log_dir)



        # ------- Step 3 + Step 4 -------
        # The IP extractor uses this combined file in benchmark_patch to build the `benchmark_ips` set.
        # Define the registry ip values: total, successful, failed and missing
        # Total has Failed (explicit failures like watchdog retry threshold exceeded, etc) + successful
        # Missing registry is the delta between benchmark_ips and total registry, i.e. those threads that are not caught by explicit
        # failure detection logic.   Currently SSH failures, either in initializaton or failed 5 SSH retries need to be tagged as 
        #failures OR untagged registry values NOT included in total registry so that they show up in missing registry
        # Failed + Successful + Missing = total + missing = benchmark_ips

        try:
            with open(benchmark_path, "r") as f:
                lines = f.readlines()
                patch7_logger.info(f"[Patch7] Runtime log line count: {len(lines)}")
                patch7_logger.info(f"[Patch7] Sample lines: {lines[:5]}")

                # 🔍 Block 1: Diagnostic check for presence of 'Public IP:'
                if any("Public IP:" in line for line in lines):
                    patch7_logger.info("[Patch7] ✅ Found at least one line with Public IP")
                else:
                    patch7_logger.warning("[Patch7] ❌ No Public IP lines found in runtime log")

                # 🔍 NEW Block: dump all candidate lines that contain "Public IP:"
                public_ip_lines = [line for line in lines if "Public IP:" in line]
                patch7_logger.info(f"[Patch7] 🔎 Lines with 'Public IP:': {public_ip_lines[:3]}")

                # 🔍 Block 2: Regex fallback tester BEFORE comprehension
#                for i, line in enumerate(lines):
#                    match = re.search(r"Public IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", line)
#                    if match:
#                        patch7_logger.info(f"[Patch7] 🔥 Line {i}: Regex matched IP: {match.group(1)}")
#                    else:
#                        if "Public IP:" in line:
#                            patch7_logger.warning(f"[Patch7] ⚠️ Line {i} has 'Public IP:' but no regex match: {line.strip()}")

#                for i, line in enumerate(lines):
#                    if "Public IP:" in line:
#                        patch7_logger.info(f"[Patch7] 🧪 Raw candidate line {i}: {repr(line)}")
#                        #match = re.search(r"Public IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", line)
#                        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
#
#                        if match:
#                            patch7_logger.info(f"[Patch7] 🔥 Line {i}: Regex matched IP: {match.group(1)}")
#                        else:
#                            patch7_logger.warning(f"[Patch7] ⚠️ Line {i} has 'Public IP:' but no regex match: {line.strip()}")

                for i, line in enumerate(lines):
                    if "Public IP:" in line:
                        patch7_logger.info(f"[Patch7] 🧪 Raw candidate line {i}: {repr(line)}")
                        
                        ip_matches = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if ip_matches:
                            patch7_logger.info(f"[Patch7] 🔥 Line {i}: Matched IPs: {ip_matches}")
                        else:
                            patch7_logger.warning(f"[Patch7] ⚠️ Line {i} has 'Public IP:' but no regex match: {line.strip()}")

                # ⚙️ Comprehension that hydrates benchmark_ips
                benchmark_ips = {
                    match.group(1)
                    for line in lines
                    #if (match := re.search(r"Public IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", line))
                    if (match := re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line))
                }
                patch7_logger.info(f"[Patch7] 💧 Hydrated IPs: {benchmark_ips}")


            total_registry_ips = set(resurrection_registry.keys())

            ## Add these to troublehsoot artifact loggin issues. These go to the patch summary logs in the artifacts of gitlab piepline

            patch7_logger.info(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
            patch7_logger.info(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")
            patch7_logger.info(f"[Patch7] Sample benchmark IPs: {sorted(list(benchmark_ips))[:3]}")
            patch7_logger.info(f"[Patch7] Sample registry IPs: {sorted(list(total_registry_ips))[:3]}")
            # add these for gitlab console
            print(f"[Patch7] Extracted benchmark_ips: {len(benchmark_ips)}")
            print(f"[Patch7] Extracted total_registry_ips: {len(total_registry_ips)}")



            # Debugs to ensure that the registry is intact from install_tomcat() which looks ok, to the resurrection_monitor() call
            print(f"[RESMON DEBUG] Resurrection registry snapshot:")
            for ip, entry in resurrection_registry.items():
                print(f"    {ip}: {entry}")

            successful_registry_ips = {
                ip for ip, entry in resurrection_registry.items()
                if entry.get("status") == "install_success"
                and entry.get("watchdog_retries", 0) <= 2
            }

            # Debugs to tell  how many IPs the above filter pulled through — and what the filter did to the full registry snapshot.
            print(f"[RESMON DEBUG] Registry IPs classified as successful: {successful_registry_ips}")



            failed_registry_ips = total_registry_ips - successful_registry_ips

            missing_registry_ips = benchmark_ips - total_registry_ips




            # Dump artifacts
            def dump_set_to_artifact(name, ip_set):
                path = os.path.join(log_dir, f"{name}_artifact.log")
                with open(path, "w") as f:
                    for ip in sorted(ip_set):
                        f.write(ip + "\n")
                patch7_logger.info(f"[Artifact Dump] {name}: {len(ip_set)} IPs dumped to {path}")

            def safe_artifact_dump(tag, ip_set):
                try:
                    dump_set_to_artifact(tag, ip_set)
                    patch7_logger.info(f"[Patch7] Artifact '{tag}' written with {len(ip_set)} entries.")
                except Exception as e:
                    patch7_logger.info(f"[Patch7] Failed to write '{tag}': {e}")
            


            if not total_registry_ips:
                patch7_logger.info("[Patch7] WARNING: total_registry_ips is empty — skipping artifact.")   
            else:
                 safe_artifact_dump("total_registry_ips", total_registry_ips)
          
            if not benchmark_ips:
                patch7_logger.info("[Patch7] WARNING: benchmark_ips is empty — skipping artifact.")
            else:
                safe_artifact_dump("benchmark_ips", benchmark_ips)
          
            if not missing_registry_ips:
                patch7_logger.info("[Patch7] WARNING: missing_registry_ips is empty — skipping artifact.")
            else:
                safe_artifact_dump("missing_registry_ips", missing_registry_ips)
          
            if not successful_registry_ips:
                patch7_logger.info("[Patch7] WARNING: successful_registry_ips is empty — skipping artifact.")
            else:
                safe_artifact_dump("successful_registry_ips", successful_registry_ips)
          
            if not failed_registry_ips:
                patch7_logger.info("[Patch7] WARNING: failed_registry_ips is empty — skipping artifact.")
            else:
                safe_artifact_dump("failed_registry_ips", failed_registry_ips)

#            dump_set_to_artifact("total_registry_ips", total_registry_ips)
#            dump_set_to_artifact("benchmark_ips", benchmark_ips)
#            dump_set_to_artifact("missing_registry_ips", missing_registry_ips)
#            dump_set_to_artifact("successful_registry_ips", successful_registry_ips)
#            dump_set_to_artifact("failed_registry_ips", failed_registry_ips)
#
            # Flag ghosts
            for ip in missing_registry_ips:
                flagged[ip] = {
                    "status": "ghost_missing_registry",
                    "ghost_reason": "no resurrection registry entry",
                    "pid": pid,
                    "timestamp": time.time()
                }
                log_debug(f"[{timestamp()}] Ghost flagged (missing registry): {ip}")

            # Flush the logger handlers to ensure all logs are written right before thread exit and summary conclusion
            for handler in patch7_logger.handlers:
                handler.flush()
            patch7_logger.info("🔄 Patch7 logger flushed successfully.")


            # Summary conclusion:
            patch7_logger.info("🧪 Patch7 reached summary block execution.")
            patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
            patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
            patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
            patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
            patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
            patch7_logger.info(f"Composite alignment passed? {len(missing_registry_ips) + len(total_registry_ips) == len(benchmark_ips)}")
        

        # try block indentation level is here.

        except Exception as e:
            patch7_logger.error(f"Patch7 exception encountered: {e}")
            patch7_logger.error("Patch7 thread likely aborted before reaching summary block.")
            log_debug(f"[{timestamp()}] Patch7 failure: {e}")

```




### Key Changes in Patch7b — Resurrection Monitor Focus

#### 1. **PID-Specific Registry Logs**
- Introduced `resurrection_registry_log_{pid}.json` and `resurrection_ghost_log_{pid}.json` for thread isolation.
- Logging is now thread-local to avoid race conditions and improve forensic traceability across concurrent workers.

#### 2. **Registry Finalization Logic**
- Each IP thread is assigned a single final tag, ensuring deterministic resurrection logic later.
- Tags like `install_success`, `ssh_retry_failure`, and watchdog-related outcomes now live in the registry.
- This tagging logic was extended from Patch6 but formally finalized in Patch7b to support Phase3 resurrection planning.

#### 3. **Ghost Net Implementation**
- The ghost log captures threads that failed to register entirely — either due to early aborts, swap contention, or silent failures.
- Designed as a fallback safety net and diagnostic tool, especially helpful when registry entries are unexpectedly missing.

#### 4. **Debug Trace Cleanup**
- Intermediate debug prints were trimmed or modularized.
- Artifact hydration logs (e.g. timing, IP state transitions) were reshaped to reduce noise and improve forensic clarity.

#### 5. **Registry Entry Normalization**
- Registry entries were auto-formatted for consistency — timestamped, tagged, and hydrated with auxiliary signals like retry counters, error traces, etc.
- This sets the stage for Patch7c’s threading collator or state summarizer.






### Troubleshooting


After extensive testing with this there is a problem with the registry being overwritten by each success process call of the
resurrection_monitor. The debugs in patch 7b helped sort out 
and locate this issue.   As a review: main() calls tomcat_worker_wrapper and tomcat_worker_wrapper calls tomcat_worker. tomcat_worker
then calls threaded_install which invokes multi-threading call to install_tomcat where the tomcat9 is installed per EC2 instance
(thread). At the end of tomcat_worker the resurrection_monitor is called (i.e., per process not per thread).


#### Debug 1:

First debug is to check the resurrection registry at the end of the install_tomcat. 
resurrection_monitor is called per process at teh end of tomcat_worker and threaded_install inside tomcat_worker eventually calls
install_tomcat per thread (EC2 instance install)

The first debug places this towards the end of install_tomcat right after the registry is updated:
(this is done per thread for each IP). The IP is tagged install_success


```
        update_resurrection_registry(ip, attempt=0, status="install_success", pid=multiprocessing.current_process().pid)

        ## Debugging code to track down the successful_registry_ips tagging issue
        # 🔍 Trace log to confirm registry tagging per thread
        try:
            registry_snapshot = dict(resurrection_registry)  # shallow copy under lock-less read
            pid = multiprocessing.current_process().pid

            print(f"[TRACE] ✅ Tagging success for IP {ip} | PID {pid}")
            print(f"[TRACE] Registry BEFORE update: {registry_snapshot.get(ip, 'Not present')}")

        except Exception as e:
            print(f"[TRACE ERROR] Snapshot read failed for {ip} | PID {pid} — {e}")
```


For this test we are running 1 thread per process, so we expect to see a registry value created for each pid.
This shows that the tagging is working fine.
The status has "install_success"

```

[TRACE] ✅ Tagging success for IP 3.86.110.71 | PID 16
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:57:54.220675', 'pid': 16}
[TRACE] ✅ Tagging success for IP 18.233.155.224 | PID 12
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:57:54.945752', 'pid': 12}
[TRACE] ✅ Tagging success for IP 44.211.140.236 | PID 18
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:57:56.949735', 'pid': 18}
[TRACE] ✅ Tagging success for IP 34.226.124.59 | PID 20
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:06.978816', 'pid': 20}
[TRACE] ✅ Tagging success for IP 35.171.158.84 | PID 17
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:07.030721', 'pid': 17}
[TRACE] ✅ Tagging success for IP 52.90.192.187 | PID 23
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:08.226420', 'pid': 23}
Installation completed on 52.90.192.187
[TRACE] ✅ Tagging success for IP 3.83.156.71 | PID 19
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:08.231899', 'pid': 19}
Installation completed on 3.83.156.71
[TRACE] ✅ Tagging success for IP 52.71.66.76 | PID 22
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:08.775509', 'pid': 22}
Installation completed on 52.71.66.76
[TRACE] ✅ Tagging success for IP 34.226.121.19 | PID 13
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:08.933181', 'pid': 13}
Installation completed on 34.226.121.19
[TRACE] ✅ Tagging success for IP 13.221.209.195 | PID 21
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:08.933393', 'pid': 21}
Installation completed on 13.221.209.195
[TRACE] ✅ Tagging success for IP 3.83.16.32 | PID 15
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:14.626423', 'pid': 15}
Installation completed on 3.83.16.32
[TRACE] ✅ Tagging success for IP 3.91.145.193 | PID 14
[TRACE] Registry BEFORE update: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-01T22:58:18.958270', 'pid': 14}
Installation completed on 3.91.145.193

```



#### Debug 2:

The next debug is for ensuring that the registry remains intact once the resurrection_monitor is called after all the 
threads are executed in the process by the threaded_install.   The resurrection_monitor is called at the very end of tomcat_worker
per process.   We expect the registry to be intact. These debugs are in the resurrection_monitor


```

            # Debugs to ensure that the registry is intact from install_tomcat() which looks ok, to the resurrection_monitor() call
            print(f"[RESMON DEBUG] Resurrection registry snapshot:")
            for ip, entry in resurrection_registry.items():
                print(f"    {ip}: {entry}")

            successful_registry_ips = {
                ip for ip, entry in resurrection_registry.items()
                if entry.get("status") == "install_success"
                and entry.get("watchdog_retries", 0) <= 2
            }

            # Debugs to tell  how many IPs the above filter pulled through — and what the filter did to the full registry snapshot.
            print(f"[RESMON DEBUG] Registry IPs classified as successful: {successful_registry_ips}")



            failed_registry_ips = total_registry_ips - successful_registry_ips

            missing_registry_ips = benchmark_ips - total_registry_ips

```


The first part of the debug2 code  prior to the successful_registry_ips comprehension look ok, but the aggregate following the successful_registry_ips
shows that each process call is overwriting the previous registry value with its thread(s) ip(s). In this case below there is 
only 1 thread per process, but the overwrite is apparent. The "Registry IPs classified as successful" should be building up
(in this case to 12 IPs), but instead is being overwritten by the latest ip. And it ends with the IP of the last process to 
finish (the .34 address below) as shown by the timestamp. In this case the successful_registry_ips only has the .34 address
which is the source of the problem.  This overwritting issue will require a new patch 7c where a thread level registry is created,
and then at the process level the thread level registry is aggregated and then after the test runs the process level registry logs
will be aggregrated (post run). This ensures that performance will not erode even though the logging is done in these three stagees,
because the buil of the aggregatino is done post run (either in the python module or in the gitlab CI/CD pipeline). I prefer to
do all of this in the python and then publish the files as artifacts through the mounted volume in the python docker container
that is executing the script (similar to the process and main level logging infra)


```

[RESMON DEBUG] Resurrection registry snapshot:
    54.146.165.2: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:11:50.033634', 'pid': 21}
[RESMON DEBUG] Registry IPs classified as successful: {'54.146.165.2'}
[RESMON DEBUG] Resurrection registry snapshot:
    54.165.79.46: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:11:50.468689', 'pid': 22}
[RESMON DEBUG] Registry IPs classified as successful: {'54.165.79.46'}
[RESMON DEBUG] Resurrection registry snapshot:
    3.92.133.149: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:11:50.705374', 'pid': 12}
[RESMON DEBUG] Registry IPs classified as successful: {'3.92.133.149'}
[RESMON DEBUG] Resurrection registry snapshot:
    44.211.164.146: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:11:50.745291', 'pid': 13}
[RESMON DEBUG] Registry IPs classified as successful: {'44.211.164.146'}
[RESMON DEBUG] Resurrection registry snapshot:
    13.218.175.13: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:11:50.756491', 'pid': 20}
[RESMON DEBUG] Registry IPs classified as successful: {'13.218.175.13'}
[RESMON DEBUG] Resurrection registry snapshot:
    54.145.134.132: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:00.936152', 'pid': 16}
[RESMON DEBUG] Registry IPs classified as successful: {'54.145.134.132'}
[RESMON DEBUG] Resurrection registry snapshot:
    54.173.82.6: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:01.208261', 'pid': 23}
[RESMON DEBUG] Registry IPs classified as successful: {'54.173.82.6'}
[RESMON DEBUG] Resurrection registry snapshot:
    54.86.2.164: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:02.601312', 'pid': 19}
[RESMON DEBUG] Registry IPs classified as successful: {'54.86.2.164'}
[RESMON DEBUG] Resurrection registry snapshot:
    13.221.99.193: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:02.791359', 'pid': 17}
[RESMON DEBUG] Registry IPs classified as successful: {'13.221.99.193'}
[RESMON DEBUG] Resurrection registry snapshot:
    54.89.141.129: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:02.993985', 'pid': 15}
[RESMON DEBUG] Registry IPs classified as successful: {'54.89.141.129'}
[RESMON DEBUG] Resurrection registry snapshot:
    18.205.117.91: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:12:12.770124', 'pid': 14}
[RESMON DEBUG] Registry IPs classified as successful: {'18.205.117.91'}
[RESMON DEBUG] Resurrection registry snapshot:
    35.173.177.34: {'status': 'install_success', 'attempt': 0, 'timestamp': '2025-08-02T00:13:01.413235', 'pid': 18}
[RESMON DEBUG] Registry IPs classified as successful: {'35.173.177.34'}


Benchmark_ips
13.218.175.13
13.221.99.193
18.205.117.91
3.92.133.149
35.173.177.34
44.211.164.146
54.145.134.132
54.146.165.2
54.165.79.46
54.173.82.6
54.86.2.164
54.89.141.129



Successful
35.173.177.34

```

### Root problem analysis with patch 7b



Resurrection registry snapshots are being overwritten per process, rather than accumulated across threads. 
That explains why `successful_registry_ips` only shows one IP per run — the last IP of the last process to complete. (In this 
simple test there was only 1 thread per process hence 1 IP being processed per process)

#### Root Cause  

- install_tomcat correctly tags each thread-level IP.
- But resurrection_monitor, called per process (By tomcat_worker), rebuilds the `resurrection_registry` from scratch, clobbering prior thread outputs.
- Even though each thread logs its IP, the final snapshot only contains one — the last thread executed in the last process to complete


#### Patch7c Objective  

- Implement **thread-level mini registries** (`thread_registry[ip] = {...}`).
- Let **resurrection_monitor** sweep and aggregate those into the **process-level registry log**.
- Perform full aggregation **post-run** across all processes via a registry collator (likely in the Python module, not CI).
- Ghost net remains unchanged unless anomalies surface.


Minimal Impact Strategy

- ✅ Keeps resurrection_monitor mostly intact.
- ✅ Preserve thread tagging logic and Patch7b’s forensic traces.
- ✅ Defer performance cost until post-mortem aggregation.
- ✅ Work seamlessly with the  Docker artifact export pipeline.






## UPDATES: part 18: Phase2d: Patches 5 and 6 in resurrection_monitor for improved ghost tracking heuristics (Failed tomcat installs) AND 512/25 (487 concurrent; 25 pooled) process testing

The 512/25 testing is required to create the ghost thread SSH failures, so that we can test the patch 6 and 7 code in the resurrection_monitor. The resurrection_ghost_log will now be created to track ghost threads that do not hit any of the conditions in patches 1-4 (watchdog STALL_RETRY_THRESHOLD, etc...)  Once we can track these elusive ghost threads we can then proceed to Phase3 of the project and resurrect the threads to complete the installation to the EC2 node.

The patches will be reviewed in detail below.


### Introduction: 

In short, there are now 2 types of resurrection logs that will be generated:

```
### Resurrection Registry Ghosts (Patches 1–5)
- These are threads that **touched the registry**
- But were flagged for watchdog timeouts, bad heuristics, early exits, etc.
- Stored in `resurrection_registry_log_<pid>.json`

###  Resurrection Ghosts (Patch 6)
- Threads that **never made it into the registry at all**
- Yet showed up in benchmark logs → meaning they ran but silently died
- Stored in `resurrection_ghost_log_<pid>.json`
```


So far, there have been no resurrection registry ghosts, so the ghosts have to be "resurrection ghosts (patch6)" type, i.e. ghost
threads that do not even make it into the registry.
The logic for tracking these down will be described below. In short, we will use the process level benchmark logs as a control list of
the IP addresses that were spawned and match that against the resurrection registry.

The benchmark logs have to be used instead of the module 1 raw AWS list of ips (which is really easy to get) because we need to 
ensure that these IP addresses have a process and thread(s) attached to them as part of the python system infrasture.
Sometimes (very rarely) an AWS instance can get stuck in initialization tests (which are checked in the python code), and these
instances never get attached to a process because they are essentially "dead" . The process benchmark logs do not catch these 
These are not designed to be SSH resurrected (install tomcat9) because the node itself is dead. These fall into an entirely separate category.

The resurrection registry is the  actual list of IPs that have been added to the registry after a successful SSH connection, or 
explicit fail of the 5 SSH retry loops, or passing the install tomcat loop, or failing the 3 retry install loop, or passing the 
watchdog timer, or failing the watchdog STALL_RETRY_THRESHOD (currently at 2). These are all the known types of thread and thread 
failure types that we can identify.

The resurrection registry ghosts would be a thread that does not have an install_success, so several of the failure items just listed 
above would qualify and it would catch these ghosts

The resurrection ghosts (Patch 6) type have no registry entry and that is why they are so hard to find.
This is the purpose of the patch 6 to the resurrection_monitor function.

Example: Thread exceeds the watchdog STALL_RETRY_THRESHOLD of 2:
If a thread exceeds the  defined `STALL_RETRY_THRESHOLD`, it will trigger this block inside `read_output_with_watchdog()`:

```
if attempt >= STALL_RETRY_THRESHOLD:
    update_resurrection_registry(ip, attempt, f"watchdog_timeout_on_{label}", pid=...)
```

This results in the following:

- ✅ It creates a resurrection registry entry for the IP (resurrection_monitor and update_resurrection_registry)
- ✅ `status` gets set to `"watchdog_timeout_on_STDOUT"` or `"watchdog_timeout_on_STDERR"` (depending on where it stalls)
- ✅ That IP shows up inside `total_registry_ips` (resurrection_nonitor)
- ✅ Patch 5 flags it as a ghost if it's not marked `"install_success"`(resurrection_monitor)
- ✅ It’s logged in `resurrection_registry_log_<pid>.json`(resurrection_monitor)

These watchdog-stalled threads are textbook registry ghost in that they tried, failed repeatedly, and got captured by the forensic 
logic in the python code.  Patch 6 doesn’t catch them because they exist in the registry. But they’re prime candidates for 
resurrection in  Phase 3
The purpose of patch 6 is to catch the ghost threads that are not caught by the logic in the python code.(not the example above) 

If this is successful in the testing we can proceed to Phase3. Once Phase3 is implemented the system will continue to be scaled up.
The maximum process count target is tentatively 800.

### Patch 5
```
        # ---------------- Begin Resurrection Registry Scan (patches 2 and 5) ----------------

        for ip, record in resurrection_registry.items():


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

```



### Patch 6

```

###### INSERT PATCH 6 HERE WITHIN THE resurrection_regisry_lock
#        # ---------------- Begin Patch 6: Ghosts with NO registry footprint ----------------
#        try:
#            benchmark_path = os.path.join(log_dir, "benchmark_combined.log")
#            with open(benchmark_path, "r") as f:
#                benchmark_ips = {
#                    match.group(1)
#                    for line in f
#                    if (match := re.search(r"Public IP:\s+(\d{1,3}(?:\.\d{1,3}){3})", line))
#                }
#
#            # Identify IPs seen in benchmark log but completely missing from resurrection registry
#            missing_registry_ips = benchmark_ips - total_registry_ips
#
#            for ip in missing_registry_ips:
#                flagged[ip] = {
#                    "status": "ghost_missing_registry",
#                    "ghost_reason": "no resurrection registry entry",
#                    "pid": pid,
#                    "timestamp": time.time()
#                }
#                log_debug(f"[{timestamp()}] Ghost flagged (missing registry): {ip}")
#
#        except Exception as e:
#            log_debug(f"[{timestamp()}] Patch 6 failure: {e}")
#        # ---------------- End Patch 6 ----------------
#
```



### Results of extensive testing

This code above (patches 5 and 6) is still missing the ghost failures because the failures were isolated to early SSH connect issues.  
The logs were methodically reviewed and it was found that of 512 nodes, 3 were unsuccessful.  But the patch6 code for 
missing_registry_ips was still zero becasue the total_registry_ips was still 512 when it should have been 509.

Steps to isolate the ghost ip threads

:
```

Step 1
First step count the actual tomcat successful in benchmark
dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_86$ grep "Install succeeded" benchmark_combined.log | wc -l
509


Step 2
Second step get a list of the actual successful tomcat install ips  from benchmark combined log
grep "Install succeeded" benchmark_combined.log \
  | grep -oE 'Public IP: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
  | awk '{print $3}' \
  | grep -Ev '^172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+' \
  | sort | uniq > expected_gitlab_ips.txt

Step 3
Third step get a list of all ips (successful and unsuccessful) in the gitlab console logs
Remove 172 addresses from the list:

grep "

\[DEBUG\]

 Process" gitlab_logs_7_27_25.txt \
  | grep -oE "'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'" \
  | tr -d "'" \
  | grep -Ev '^172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+' \
  | sort | uniq > all_gitlab_ips_clean.txt


dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads$ cat all_gitlab_ips_clean.txt | wc -l
512

Step 4
Fourth step verify  between clean (512) and expected/successful (509)
all_gitlab_ips_clean.txt 512
expected_gitlab_ips.txt 509


Step 5
Fifth step sort the 2 logs of 512 and 509
sort all_gitlab_ips_clean.txt > sorted_gitlab_ips.txt
sort expected_gitlab_ips.txt > sorted_expected_ips.txt

dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_86$ ls | grep sorted
sorted_expected_ips.txt
sorted_gitlab_ips.txt


Step 6
Sixth step do a diff between the two sorted files
comm -13 sorted_expected_ips.txt sorted_gitlab_ips.txt > ghost_gitlab_ips.txt

dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_86$ comm -13 sorted_expected_ips.txt sorted_gitlab_ips.txt > ghost_gitlab_ips.txt
dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_86$ cat ghost_gitlab_ips.txt
18.212.250.15
3.95.60.23
52.91.226.33

These are finally the elusive ghosts of the 512 test.
note: comm -13: hides lines only in the benchmark (file1) and lines common to both—leaving just the GitLab IPs that didn't make it to the "Install succeeded" club.


Step 7
Seventh step grep for these ips in the gitlab console logs and see what the conversation consists of and compare to A good ip (see next topic, below)
bash
while read ip; do
  grep "$ip" gitlab_logs_7_27_25.txt >> suspect_ip_logs.txt
done < ghost_gitlab_ips.txt

This will give us the lines in gitlab console logs that have these ip addreses. This won't cover all conversation as all the lines are
not tagged with the IP but it will give us an idea of what happened.



Examples:
dmastrop@LAPTOP-RAT831LJ:/mnt/c/Users/davem/Downloads/logs_86$ cat suspect_ip_logs.txt [DEBUG] Process 287: IPs = ['18.212.250.15'] Attempting to connect to 18.212.250.15 (Attempt 1) [DEBUG] Process 193: IPs = ['3.95.60.23'] Attempting to connect to 3.95.60.23 (Attempt 1) [DEBUG] Process 250: IPs = ['52.91.226.33'] Attempting to connect to 52.91.226.33 (Attempt 1)


**There is no more occurrence of these ips in the entire log other than this:

[DEBUG] Process 287: IPs = ['18.212.250.15'] Attempting to connect to 18.212.250.15 (Attempt 1) [DEBUG] Process 193: IPs = ['3.95.60.23'] Attempting to connect to 3.95.60.23 (Attempt 1) [DEBUG] Process 250: IPs = ['52.91.226.33'] Attempting to connect to 52.91.226.33 (Attempt 1)

These clearly indicate a slient SSH connect abort with no failure response code. Patch8 will have to catch these kinds of failures and
tag them accordingly in the registry
```


The reason for this is that the registry is allowing thread entires without any tag whatsoever (the case of early SSH
connect failures currently falls into this condition. This will be fixed shortly).  That has to be prevented and the
total_registry_ips must only contain tagged registry values with explicit python code failure tags (For example exceeding
watchdog retries) or install_succeeded tag. Thus total_registry_ips = failed_registry_ips + successful_registry_ips
and missing_registry_ips = benchmark_ips - total_registry_ips. In this way missing_registry_ips will catch only cases
where some sort of issue prevents a tag on the registry (very rare, for example a node not passing AWS status checks and
getting stuck in that condition). 

benchmark_ips will continue to be the standard by which runtime registry threads are measured.

Now to catch the SSH connect early failures we will need patch8, but before that patch7 to create log artifacts for the following:

```
            patch7_logger.info(f"Total registry IPs: {len(total_registry_ips)}")
            patch7_logger.info(f"Benchmark IPs: {len(benchmark_ips)}")
            patch7_logger.info(f"Missing registry IPs: {len(missing_registry_ips)}")
            patch7_logger.info(f"Successful installs: {len(successful_registry_ips)}")
            patch7_logger.info(f"Failed installs: {len(failed_registry_ips)}")
```


Patch7 will be in the next update section and will have the statistics generated above so that we can see these different types
of registry tagged thread ips. Once we have this in place phase8 will tag the SSH connect ghosts (they will be included in
total_registry_ips and failed_registry_ips and can be selectively identified for resurrection in Phase3 of this project.

Patch 7 will replace patch 6 completely.

Now that the elusive ghosts have been identified (early SSH connect aborted silent failures), we can create patch7 to report and track
these threads in the registry and also patch8 to add to the SSH connect code tagging (ssh_initialized_failed and ssh_retry_failed)
for silient SSH early connect fails (current ghost threads) and for SSH connections that fail all 5 retries of the outer loop.
Just as a review: there is an outer SSH connect loop (5 retries) and a loop inside that for 3 install tomcat9 retries and then inside
each of those a max of 2 watchdog timeout retries.  We are working with the outer loop here.  With these changes the SSH connect
fails will show up in total_registry_ips as well as failed_registry_ips where total_registry_ips = successful_registry_ips +
failed_registry_ips.





## UPDATES: part 17: Phase2c: Add uuid to the benchmark process level logs and ramp up the testing to 480/25 with the updated Phase2 code

Added uuid to the process level benchmark logs in threaded_install() function

```
### This is the wrapped multi-threading code for benchmarking statistics
    ### Make sure to indent this within the tomcat_worker function!
    def threaded_install():
        import uuid # This is for adding uuid to the logs. See below

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_info]


## Add uuid since the pids are reused in hyper-scaling. This is not absolutely required as my log files do use
## uuid to differentiation same pid benchmark logs but adding to content of the logs will help in the future
## for logging forenscis


            for future in as_completed(futures):
                ip, private_ip, result = future.result()
                pid = multiprocessing.current_process().pid
                thread_uuid = uuid.uuid4().hex[:8]

                if result:
                    logging.info(f"[PID {pid}] [UUID {thread_uuid}] ✅ Install succeeded | Public IP: {ip} | Private IP: {private_ip}")
                    successful_ips.append(ip)
                    successful_private_ips.append(private_ip)
                else:
                    logging.info(f"[PID {pid}] [UUID {thread_uuid}] ❌ Install failed | Public IP: {ip} | Private IP: {private_ip}")
                    failed_ips.append(ip)
                    failed_private_ips.append(private_ip)


```

### 480/25

To test the resurrection monitor logging need to ramp up the stress and thread contention to see if we can instigate the SSH
thread failures again so that we can implement the Phase3 code to resurrect the faulty threads.










## UPDATES: part 16 Hyper-scaling of processes 450/25 and 480/25: REFACTOR SSH 4 -- Phase2: resurrection_registry (Phase2a), resurrection_monitor (Phase2a), and resurrection_gatekeeper (Phase2b) AND patch 1 for registry success fingerprint AND patches 2-4 for improved ghost heuristics in resurrection_monitor


This is currently undergoing testing.  May have to increase the sample_probability to catch swap statistics for more than the current 10% of the processes.  This is expensive in terms of CPU and execution time and will only be increased temporarily to troubleshoot ghost failures, if required.


The core code block added here is the resurrection_gatekeeper Phase2b code
This has the resurrection_gatekeeper which will use the data from the read_output_with_watchdog function above to determine if the thread actually is a resurrection candidate and prevent false postives for resurrection candidates.   We only want to resurrect truly dead threads
Later on in Phase3 will reinstall tomcat on these threads.
Phase 4 will adapatively do this based upon current heuristics and system stress indicators (ML)
The saturation defense(see code block below) is required because there may be other corner cases whereby the thread is not successfully being resurrected  (Phase3). For these threads we  need to flag them for further investigation. This could be for example with a flapping node or 
misclassified IP address, etc....




### resurrection_registry code

```

# ------------------ RESURRECTION REGISTRY + WATCHDOG HOOKS ------------------
# Purpose: Detect stalled STDOUT/STDERR reads during SSH execution inside install_tomcat()
#          and flag repeated failures for postmortem analysis or thread resurrection.
# Scope:   Shared across all threads and processes launched from tomcat_worker()
# Output:  Structured JSON log via resurrection_monitor() at end of each process lifecycle
# ---------------------------------------------------------------------------


from datetime import datetime
import threading

WATCHDOG_TIMEOUT = 90
RETRY_LIMIT = 3
SLEEP_BETWEEN_ATTEMPTS = 5
STALL_RETRY_THRESHOLD = 2

resurrection_registry = {}
resurrection_registry_lock = threading.Lock()

def update_resurrection_registry(ip, attempt, status):
    with resurrection_registry_lock:
        resurrection_registry[ip] = {
            "status": status,
            "attempt": attempt,
            "timestamp": datetime.now().isoformat()
        }

def read_output_with_watchdog(stream, label, ip, attempt):
    start = time.time()
    collected = b''
    while True:
        if stream.channel.recv_ready():
            try:
                collected += stream.read()
                break
            except Exception as e:
                print(f"[{ip}] ⚠️ Failed reading {label} (Attempt {attempt}): {e}")
                break
        elapsed = time.time() - start
        if elapsed > WATCHDOG_TIMEOUT:
            print(f"[{ip}] ⏱️  Watchdog timeout on {label} read (Attempt {attempt}).")
            if attempt >= STALL_RETRY_THRESHOLD:
                print(f"[{ip}] 🔄 Multiple stalls detected. Flagging for resurrection.")
                update_resurrection_registry(ip, attempt, f"watchdog_timeout_on_{label}")
            break
        time.sleep(1)
    return collected.decode()


```






### resurrection_gateway code

```
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
```





### Integration with REFACTOR SSH 4 code block (resurrection_registry and resurrection_gateway function calls) and patch1 to install_tomcat():


This code is in the large install_tomcat() function. Patch 1 is placed at the end of this install_tomcat() function to fingerprint
successful thread tomcat installs so that the resurrection_monitor can separate them out and not create a resurrection_registry_log 
file for them. See below for patch1



```
# REFACTOR SSH 4 - Phase 2 The new resurrection policy to flag connecitons that have failed 2 watchdog timeouts
## and update resurrection registry.  Multiple stalls detected. Flagging for resurrection
## Note the read_output_with_watchdog function and an new function update_resurrection_registry have been added/moved to just
## above the main tomcat_worker function above. This makes them global so that we can utilize the resurrection monitor
## that will log the resurrection registry candidates.   These functions are now global to tomcat_worker (not indented).
## The comment # ------------------ RESURRECTION REGISTRY + WATCHDOG HOOKS ------------------ flags the block.
## The read_output_with_watchdog calls the update_resurrection_registry function



        for idx, command in enumerate(commands):
            for attempt in range(RETRY_LIMIT):
                try:
                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)

                    stdout.channel.settimeout(WATCHDOG_TIMEOUT)
                    stderr.channel.settimeout(WATCHDOG_TIMEOUT)

                    stdout_output = read_output_with_watchdog(stdout, "STDOUT", ip, attempt)
                    stderr_output = read_output_with_watchdog(stderr, "STDERR", ip, attempt)

                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")


                    ## Insert the call to the resurrection_gatekeeper here now that read_output_with_watchdog has collected all the relevant 
                    ## arguments for this function call

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
                        update_resurrection_registry(ip, attempt, "gatekeeper_resurrect")
                        print(f"[{ip}] 🛑 Resurrection triggered by gatekeeper logic.")
                    else:
                        print(f"[{ip}] ✅ Resurrection blocked — gatekeeper verified node success.")


                    if "E: Package 'tomcat9'" in stderr_output:
                        print(f"[{ip}] ❌ Tomcat install failure.")
                        ssh.close()
                        return ip, private_ip, False

                    if "WARNING:" in stderr_output:
                        print(f"[{ip}] ⚠️ Warning ignored: {stderr_output.strip()}")
                        stderr_output = ""

                    if stderr_output.strip():
                        print(f"[{ip}] ❌ Non-warning stderr received.")
                        ssh.close()
                        return ip, private_ip, False

                    print(f"[{ip}] ✅ Command succeeded.")
                    time.sleep(20)
                    break  # Success
   
                except Exception as e:
                    print(f"[{ip}] 💥 Exception during exec_command (Attempt {attempt + 1}): {e}")
                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)

                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()


        ssh.close()
        transport = ssh.get_transport()
        if transport:
            transport.close()

        # This is patch1:  ✅ Log registry entry for successful installs. This prevents empty registry entries (successes) 
        # from creating a resurrection log. This will ensure that all installation threads leave some sort
        # of registry fingerprint unless they are legitimate early thread failures.
        update_resurrection_registry(ip, attempt=0, status="install_success")


        print(f"Installation completed on {ip}")
        return ip, private_ip, True
```




### resurrection_monitor code: patches 2-4 to resurrection_monitor() for successful threads still creating resurrection_registry_logs

```
def resurrection_monitor(log_dir="/aws_EC2/logs"):
    pid = multiprocessing.current_process().pid
    log_path = os.path.join(log_dir, f"resurrection_registry_log_{pid}.json")

    flagged = {}
    with resurrection_registry_lock:
        for ip, record in resurrection_registry.items():


            # 🛑 Skip nodes that completed successfully. This is patch2 to address this issue where we are
            # seeing successful installations having resurrection logs created. Patch1, creating a registry
            # fingerprint for successful installs at the end of install_tomcat() did not address this problem
            # Patch1 is at the end of install_tomcat() with install_success fingerprint stamping.
            if record.get("status") == "install_success":
                continue


            if "timeout" in record["status"] or record["attempt"] >= STALL_RETRY_THRESHOLD:
                flagged[ip] = record


# Replace patch3 with patch4. Still getting {} resurrection logs for successful threads. This will ensure
# no logs are created for these. This resolved the issue.

    # 🔍 Global success check — avoids false early_exit logs
    success_found = any(
        record.get("status") == "install_success"
        for record in resurrection_registry.values()
    )
    if not flagged and not success_found:
        flagged["early_exit"] = {
            "status": "early_abort",
            "reason": "No registry entries matched. Possible thread exit before retry loop.",
            "pid": pid,
            "timestamp": time.time()
        }

    # ✅ Only log if flagged exists. This will ensure that no {} empty resurrection log files are created for the
    # successful installation threads
    if flagged:
        os.makedirs(log_dir, exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(flagged, f, indent=4)
```


### The resurrection_monitor call is at the end of the tomcat_worker() function that is called by tomcat_worker_wrapper()
### The wrapper is required for process level logging

```
###### Call the resurrection monitor function. This is run per process. So if 5 threads in a process it the resurrection registry
###### will have scanned for 5 EC2 instance installs and logged any that have met the resurrection_gateway criteria. 
###### These are resurrection
###### candidates. The monitor will create the log for the process and list those threads. Thus for 450 processes with 1 thread each
###### for example, there will be 450 of these log files. Will aggregate them later.  This is the end of the tomcat_worker() function:

    resurrection_monitor()

```

tomcat_worker() is a very large main function in module2 and preceeds the main() function at the end of this module
main() has high level logging orchestration and multi-processing of the chunk_size blocks that the ThreadPoolExecutor works on
with multi-threading in tomcat_worker()
tomcat_worker_wrapper() supports the process level logging orchestration at the individual process and thread level.
The resurrection_monitor needs to be called for each process that is processing the chunk_size blocks through the multi-threading
ThreadPoolExecutor as described above.


 




## UPDATES: part 15 Hyper-scaling of processes 450/25: REFACTOR SSH 3 -- Phase1 to deal with the ghosts.

This is the first phase of refactoring to deal with the ghost issue of UPDATE part 14 below.


Refactor for Retry + Watchdog Logic  
This version:
-Adds a retry loop for `exec_command` execution
-Wraps `stdout.read()` and `stderr.read()` with a watchdog timer using `recv_ready()`
-Monitors for stalls and retries intelligently

Initially run this with a 450/25 test and then ramp it up to 480/25


The refactored code is below:

```

## REFACTOR SSH 3 – Phase 1: Retry + Watchdog Protection:

from datetime import datetime
import time

WATCHDOG_TIMEOUT = 90
RETRY_LIMIT = 3
SLEEP_BETWEEN_ATTEMPTS = 5

def read_output_with_watchdog(stream, label, ip):
    start = time.time()
    collected = b''
    while True:
        if stream.channel.recv_ready():
            try:
                collected += stream.read()
                break
            except Exception as e:
                print(f"[{ip}] ⚠️ Failed reading {label}: {e}")
                break
        if time.time() - start > WATCHDOG_TIMEOUT:
            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read.")
            break
        time.sleep(1)
    return collected.decode()

for idx, command in enumerate(commands):
    for attempt in range(RETRY_LIMIT):
        try:
            print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
            stdin, stdout, stderr = ssh.exec_command(command, timeout=60)

            stdout.channel.settimeout(WATCHDOG_TIMEOUT)
            stderr.channel.settimeout(WATCHDOG_TIMEOUT)

            stdout_output = read_output_with_watchdog(stdout, "STDOUT", ip)
            stderr_output = read_output_with_watchdog(stderr, "STDERR", ip)

            print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
            print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")

            if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
                print(f"[{ip}] ❌ Tomcat install failure.")
                ssh.close()
                return ip, private_ip, False

            if "WARNING:" in stderr_output:
                print(f"[{ip}] ⚠️ Warning ignored: {stderr_output.strip()}")
                stderr_output = ""

            if stderr_output.strip():
                print(f"[{ip}] ❌ Non-warning stderr received.")
                ssh.close()
                return ip, private_ip, False

            print(f"[{ip}] ✅ Command succeeded.")
            time.sleep(20)
            break  # Command succeeded, no need to retry

        except Exception as e:
            print(f"[{ip}] 💥 Exception during exec_command: {e}")
            time.sleep(SLEEP_BETWEEN_ATTEMPTS)

        finally:
            stdin.close()
            stdout.close()
            stderr.close()

ssh.close()
transport = ssh.get_transport()
if transport:
    transport.close()
print(f"Installation completed on {ip}")
return ip, private_ip, True
```




### Code architecture (REFACTOR SSH 3 Phase1 code)


1. Retry Logic: Layered Around `exec_command`

```
for attempt in range(RETRY_LIMIT):
    ...
    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
```

-What changed from REFACTOR2:  
  Previously, `exec_command()` did have retry mechanisim but it was static and not structured.
-REFACTOR3 enhancement:  
  Adds a retry loop with:
  -Attempt counter
  -Error catching for exceptions
  -Delay (`SLEEP_BETWEEN_ATTEMPTS = 5`) between tries

Handle transient SSH failures gracefully, avoiding thread collapse from one-off glitches.

---

2. Watchdog: Wrapped Around `stdout.read()` and `stderr.read()`

```
def read_output_with_watchdog(stream, label, ip):
    ...
    while True:
        if stream.channel.recv_ready():
            collected += stream.read()
            break
        if time.time() - start > WATCHDOG_TIMEOUT:
            print(f"[{ip}] ⏱️ Watchdog timeout on {label} read.")
            break
        time.sleep(1)
```

-Core behavior**:
  -Starts a timer when `read_output_with_watchdog()` begins.
  -Repeatedly checks: `stream.channel.recv_ready()` → meaning SSH output is available.
  -If nothing arrives within 90 seconds (`WATCHDOG_TIMEOUT`), logs a timeout and exits read loop.

  This pattern prevents indefinite blocking on `.read()`, which was a major silent failure mode in earlier runs—especially when swap pressure or thread stalls occurred.

Avoid deadlock where thread sits inside `.read()` forever. Watchdog times out after no recv signal.


3. Smart Decision Tree After Output Read (Carry over from the previous code)

```
if "E: Package 'tomcat9'" in stderr_output:
    return ip, private_ip, False
if "WARNING:" in stderr_output:
    stderr_output = ""
if stderr_output.strip():
    return ip, private_ip, False
print(f"[{ip}] ✅ Command succeeded.")
```

-The thread **explicitly checks for known failure patterns** in `stderr`.
-If none found → success is logged → thread sleeps briefly → exits retry loop early

Avoid retrying after a confirmed success and clean up gracefully.


4. Watchdog Effectiveness (Why It’s Passive in Phase 1)

-The watchdog logs timeout but does not actively terminate or restart the thread.
-The system still proceeds to `stdout.close()`, etc., and may retry if configured—but the watchdog isn’t intercepting deeper stalls or auto-repairing.

In a nutshell, the watchdog is not fast enough to interrupt retry spirals.

If a thread stalls mid-read but `recv_ready()` stays False due to system stress, the watchdog just times out after 90 seconds and logs the event—it doesn’t kill the thread or spawn a backup. So the retry spiral continues until RETRY_LIMIT(outer loop)  is exhausted.


#### Thread simulator timeline trace examples

FAILURE CASE:


🧵 Simulated Thread Lifecycle: Phase 1 Instrumentation in Action


```
⏱️ T+00s — Thread starts
  → [192.168.1.42] [00:00:01] Command 1/4: apt update (Attempt 1)

⏱️ T+03s — SSH command dispatched
  → ssh.exec_command() issued
  → stdout/stderr stream established

⏱️ T+04s — Entering Watchdog read loop for STDOUT
  → stream.channel.recv_ready() = False
  → start timer...

⏱️ T+35s — Still waiting for recv_ready()
  → stdout.read() not triggered yet
  → Watchdog loop continues...

⏱️ T+91s — Timeout threshold exceeded (WATCHDOG_TIMEOUT = 90)
  → ⏱️ Watchdog timeout on STDOUT read.
  → exits `read_output_with_watchdog()` with empty output

⏱️ T+92s — Switches to STDERR read
  → stream.channel.recv_ready() = False again

⏱️ T+182s — ⏱️ Watchdog timeout on STDERR read.
  → Still no data → possible stall or swap starvation

⏱️ T+183s — Evaluates output:
  → stdout_output = ""
  → stderr_output = ""

⏱️ T+184s — Flags failure:
  → Non-warning stderr received (even if empty)
  → ssh.close() → return ip, private_ip, False

⏱️ T+185s — Thread terminates
  → Final log: ❌ Non-warning stderr received.
```


-The watchdog loops for 90 seconds, checking once per second whether output is available.
-If `recv_ready()` never returns `True` (e.g., thread stall or remote process lock), it logs timeout but doesn’t retry the read.
-The outer retry loop can then try again, if under `RETRY_LIMIT`.
-If all retries(outer loop currently set to 3) hit watchdog timeouts, thread exits without installing anything → failure traced in logs.





SUCCESS CASE:

✅ Successful Scenario Variant:

```
⏱️ T+04s — stream.channel.recv_ready() = True
  → stdout.read() triggered → output collected
⏱️ T+05s — stderr.read() triggered → contains only "WARNING:"
  → Warning filtered → stderr_output = ""
⏱️ T+06s — Success logged
  → ✅ Command succeeded.
  → thread sleeps 20s then moves to next command
```









### Forensic analysis of the 450/25 run with the  REFACTOR SSH 3 code above


The testing with the 450/25 processes using the REFATOR SSH3 code above resulted in 4 total failures of the 450 instances. The good thing 
about the forencsic analsysis of all 4 failures is that they all have a simlar signature and root cause. Phase 2 (SSH REFACTOR4) 
and Phase 3 (SSH REFACTOR5)  code will be used to resurrect the thread based upon the nature of the failures revealed below. 



#### Failure rate analysis

-Current run: 4 failures / 450 threads → ~0.89%
-Previous run: 7 failures / 450 threads → ~1.56%
-Relative improvement: ~43% reduction in thread-level faults  
  While this isn’t statistically significant in isolation (low sample size), the downward trend is meaningful, especially under similar swap contention
 

#### Forensic observations

 🔄 Retry Footprint
-The failed threads did show retry behavior, but 3 of them terminated without reaching `"Installation completed"`—indicative of either retry exhaustion or watchdog cutoff.
-One failure exhibited a late retry spiral around timestamp `23:05:23`, coinciding with near-max swap pressure.

⏱️ Watchdog Visibility
-Watchdog messages were present throughout the GitLab logs, confirming that Phase 1 instrumentation is alive.
-However, watchdog detection lag was observable—its timestamp trails slightly behind actual exit patterns in at least 2 failures.

🧵 Thread Mapping (PID Trace)
-`benchmark_combined` (process leve logs) aligned PID traces of all failures with GitLab thread logs.
-All 4 failed threads had distinct timestamp gaps in their activity, suggesting deadlock or incomplete spawn recovery.

💾 Swap Pressure Impact
-The `main_8` (process orchestration level)  log revealed peak swap usage at 99.8 around 23:05–23:06.
-This is significant: All 4 failures occurred within ±30s of that peak, strongly implicating memory starvation or swap collision.
-CPU remained stable, ruling out processor thrash—this was a memory-centric fault cluster.
-So memory-centric fault cluster theory is correct. This is causing the remaining falure behavior in this hyper-scaling test case.


🧠 What Phase 1 Seems to Fix
-Clear retry traceability and watchdog broadcast visibility are now present.
-Failure count dropped under same conditions.
-Threads are behaving more predictably under swap duress.

⚠️ What Phase 1 Misses
-Watchdog reaction speed isn’t fast enough to interrupt retry spirals.
-No fail-safe trigger from swap threshold itself.
-Still no thread resurrection or fallback routing when execution stalls. Thread resurrection will be a key objective for Phase2 code



#### Major shortcoming of the Phase1 code


Logs show that some failure traces had a ~30 second lag between the actual thread breakdown and when the watchdog log entry appeared. This matters because:

-Retry spirals were underway—some threads kept retrying despite being in a compromised state.
-If the watchdog were faster, it could have either:
  -Terminated the thread proactively
  -Flagged the condition sooner, reducing system resource waste or improving visibility

That delay means the watchdog is passive/reactive, and not assertive/proactive. It observes failure but doesn’t intervene until it’s slightly too late, especially under swap contention where every second counts.
The ultimate objective is to design code to detect the issue through the watchdog and the cap retries and resurrect the thread (see below)

The Phase 1 instrumentation confirms the watchdog is visible and reporting, but not yet fine-tuned to interrupt retry loops or prevent silent exits in real time. 


#### Log timeline example of falure case 

📜 Thread Lifecycle Timeline: Failure Under Phase 1 Watchdog

Time          | Event Type                   | Description
--------------|------------------------------|-----------------------------------------------------
23:04:45      | 🧵 Thread X Retry Begins     | Thread starts retry sequence after connection fail
23:04:52      | 🔁 Retry #2                  | Thread still retrying—no “Installation completed” yet
23:05:10      | 💾 Swap Hits 99.8%           | System enters swap saturation (confirmed in main log)
23:05:17      | 🧠 Thread X Appears Stalled  | No progress, retry loop persists silently
23:05:22      | 🔍 Watchdog Triggers         | Watchdog logs detection of stalled thread
23:05:25      | ❌ Thread X Terminates       | Final exit without success—missing “Installation completed”

After 3 retries of the outer loop the thread terminates.



-7–10 seconds of retry before system stress builds
-Thread stalls just as swap peaks, entering a retry spiral
-Watchdog logs event ~5 seconds later, suggesting it’s polling or responding on a timer
-No intervention or resurrection logic, thread exits unsuccessfully

This pattern repeats with subtle variations across the other failed threads. The watchdog _sees_ the collapse, but doesn’t yet _prevent_ it.



#### SUMMARY of forensics


Based on the GitLab logs and failure behavior, those 4 threads went through all 3 allowed attempts (`RETRY_LIMIT = 3`), and each time:

-The `exec_command()` was issued successfully.
-The `read_output_with_watchdog()` hit the 90-second timeout without receiving data.
-No recognizable `"Installation completed"` or recovery outputs were received.
-After all 3 tries, the outer loop was exhausted, triggering a final exit with a failure log.

This pattern maps perfectly with the forensic findings: threads did not crash outright—they slowly _expired_ through retry spirals that couldn’t reach completion. The watchdog caught the stall and logged it, but it didn’t actively rescue the thread or short-circuit the spiral. That’s why these still registered as failures.

The fact that all 4 followed the same retry exhaustion pathway is good  news—it gives a predictable failure signature, which means Phase 2 can directly intercept and intervene right at the second timeout, or even earlier based on system load.(see below)



### Next Steps for failure remediation


📦 Phase 2 Suggestions
-Active thread monitoring: Timestamp heartbeat interval (e.g. every 10s) and detect last-action age.
-Retry ceiling control: Cap retries dynamically based on swap/CPU thresholds.
-Thread resurrection logic: Spawn fallback thread if target PID fails within window.

🧬 Phase 3 Concepts
-Swap-aware watchdog logic: Watchdog starts monitoring memory thresholds, not just thread stalls.
-Final log injection: Failed threads stamp failure type into a summary log for easier postmortem.

-Phase 2 would tag the retry window and monitor for retry saturation, triggering a proactive kill or resurrection before swap collapse.
-Phase 3 could detect memory contention and throttle retries, or restart the thread with fresh state before it hits the wall.









## UPDATES: part 14 Hyper-scalling of processes 450/25: REFACTOR SSH 2, SSH connect issues, log forencsics and initial code refactoring


After using REFACTOR SSH 1 code block, used this block to dig deeper in to the issue.


```
## REFACTOR SSH 2:


        from datetime import datetime

        for idx, command in enumerate(commands):
            for attempt in range(3):
                try:
                    print(f"[{ip}] [{datetime.now()}] Command {idx+1}/{len(commands)}: {command} (Attempt {attempt + 1})")
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)


                    ## Add this timout code to detect why some instances are silently failing without hitting my except block below
                    ## this will force it out of the try loop to execept bloc.

                    # 🔒 Ensure the VPS doesn’t hang forever waiting on output
                    stdout.channel.settimeout(90)
                    stderr.channel.settimeout(90)

                    stdout_output = stdout.read().decode()
                    stderr_output = stderr.read().decode()

                    print(f"[{ip}] [{datetime.now()}] STDOUT: '{stdout_output.strip()}'")
                    print(f"[{ip}] [{datetime.now()}] STDERR: '{stderr_output.strip()}'")

                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
                        print(f"[{ip}] [{datetime.now()}] ❌ Package install failure. Exiting early.")
                        ssh.close()
                        return ip, private_ip, False

                    if "WARNING:" in stderr_output:
                        print(f"[{ip}] [{datetime.now()}] ⚠️ Warning ignored: {stderr_output.strip()}")
                        stderr_output = ""

                    if stderr_output.strip():
                        print(f"[{ip}] [{datetime.now()}] ❌ Non-warning error output. Command failed.")
                        ssh.close()
                        return ip, private_ip, False

                    print(f"[{ip}] [{datetime.now()}] ✅ Command succeeded.")
                    time.sleep(20)

                except Exception as e:
                    print(f"[{ip}] [{datetime.now()}] 💥 Exception during exec_command: {e}")
                    ssh.close()
                    return ip, private_ip, False

                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()


        ssh.close()
        transport = ssh.get_transport()
        if transport is not None:
            transport.close()
        print(f"Installation completed on {ip}")
        return ip, private_ip, True

```



In the latest test run had to increase the swap to 20GB to prevent the VPS fron hanging. Once did that the 450/25 test used about 17GB of the 20GB swap and I was able to see 7 failures with the code above.
Correlating the gitlab console logs with the debug above with the process level and  main pooling level orchestration logs revealed the following:

 7 Failures Isolated
-All occurred between timestamps [T+14min to T+16min], deep into the 450/25 cycle
-5 match the ghost profile: no `Installation completed` marker, no exit status, hung `recv()` with no output
-2 exited prematurely but did execute `exec_command()`, indicating a socket or fork failure downstream

Ghost Indicators:
-Threads hung at `channel.recv(1024)` without exception
-No log entry after `exec_command()` for those cases
-Swap was above 16.8GB—suggesting buffer delay or scheduler stalls, not memory depletion

Process-Level Logs:
-Missing heartbeat timestamps on 5 processes → confirms they stalled post-connection
-The others show clean command dispatch but dead ends in channel echo collection

Main Log Trace:
-Dispatcher launched all 25 in that burst correctly
-5 stuck at recv with no retries
-No thread timeout logic triggered → perfect test case for inserting watchdogs later


These are the 7 failed threads:

| Thread ID | Timestamp     | Type         | Symptom                                | Suggest Fix         |
|-----------|---------------|--------------|----------------------------------------|----------------------|
| #112      | T+14:02       | Ghost        | No output, stuck at `recv()`           | Watchdog + retries   |
| #127      | T+14:45       | Early Exit   | `exec_command` done, no completion log | Exit code check      |
| #135      | T+15:04       | Ghost        | Silent thread, no further output       | Force termination    |
| #142      | T+15:17       | Ghost        | Stalled post-command                   | Retry + backoff      |
| #158      | T+15:39       | Ghost        | Socket hung, swap rising               | Launch stagger       |
| #163      | T+15:52       | Early Exit   | Command dropped early                  | Retry w/ delay       |
| #170      | T+16:02       | Ghost        | No output captured                     | Watchdog             |



Based uon this: The code solution to this involves implementing code changes in the three folowing areas below:
The Ghost and Early Exit would have resolved the 7 thread failures in the last run.


Three types of general failures:

| Failure Type     | What Happens                           | Python Symptom                     | Fix Strategy                          |
|------------------|----------------------------------------|-------------------------------------|----------------------------------------|
| Timeout          | Channel blocks too long                | `socket.timeout` raised             | Retry with exponential backoff        |
| Stall (Ghost)    | Output never received, no error        | `None` from `recv()` or hangs       | Watchdog timer + force exit           |
| Early Exit       | Channel closes before command completes| `exit_status_ready()` too soon      | Check exit code + validate output     |





### Failure type one: Timeout


```
channel.settimeout(90)
channel.exec_command(cmd)
stdout = channel.recv(1024)  # <--- blocks too long, then raises socket.timeout
```

-A `socket.timeout` exception
-No output received within the expected window
-Easily caught with `try/except`



Possible fix to introdcue into the code

```
for attempt in range(3):
      try:
          stdout = channel.recv(1024)
          break
      except socket.timeout:
          time.sleep(5)
```


Also consider tightening or relaxing `settimeout()` depending on system load





### Failure type two: Stall failures(Ghost)

The channel call doesn’t raise an error—it just sits indefinitely or returns `None`.


```
stdout = channel.recv(1024)  # returns None, never throws
```

-No exception is raised
-The thread appears "alive" but makes no progress
-Worker pool gets clogged silently



For these we need to first detect them

-Use forensic timestamps to show that:
  -The `exec_command()` was sent
  -No output was received after reasonable delay
-Inject manual inactivity watchdogs:

```
  start = time.time()
  while True:
      if channel.recv_ready():
          stdout = channel.recv(1024)
          break
      if time.time() - start > 90:
          raise RuntimeError("SSH stall detected")
      time.sleep(1)
```





### Failure type three: Early exit

Here, the process exits before completing SSH output collection. 

These are caused by the following:

-Fork pressure
-Swap delays
-Broken pipe in the SSH stream



Detection involves the following:

-`"Installation completed"` never logged
-Unexpected thread exit without traceback
-`channel.exit_status_ready()` == True but with `None` output


Intercept these with the following code:

```
status = channel.recv_exit_status()
if status != 0:
    logger.warn("Command exited early or failed silently")
```









## UPDATES: part 13: Hyper-scaling of processes (400+): SSH connect issues, REFACTOR SSH 1,  and troubleshooting and log forensics and correlation

After doing foresensic correlation between the process level logs, the main() process orchestration logs and the gitlab
console logs, there are some areas that have been indentified that are causing the tomcat9 failure installations at 
process counts of 400 and above. These are mainly due to swap and RAM contention and memory thrashing and the effect
that this has in a susceptible area of the code below.

The logs consisted of a 450/0 (450 processes with no pooling) and a 450/25 (450 processes with 25 of them pooled). Both of 
these tests revealed the weakness in the area of code below.

The main area of code that needs to be refactored is below.  This area of code is located in install_tomcat which is in tomcat_worker which is in tomcat_worker_wrapper which is called from main() through the 
multiprocessing.Pool method below:

```
   try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
```


The code block that needs work is this part:

```
        for command in commands:
            for attempt in range(3):
                try:
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
                    stdout_output = stdout.read().decode()
                    stderr_output = stderr.read().decode()

                    print(f"Executing command: {command}")
                    print(f"STDOUT: {stdout_output}")
                    print(f"STDERR: {stderr_output}")

                    # Check for real errors and ignore warnings 
                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
                        print(f"Installation failed for {ip} due to package issue.")
                        ssh.close()
                        return ip, private_ip, False

                    # Ignore specific warnings that are not critical errors
                    if "WARNING:" in stderr_output:
                        print(f"Warning on {ip}: {stderr_output}")
                        stderr_output = ""

                    if stderr_output.strip():   # If there are any other errors left after ignoring warnings:
                        print(f"Error executing command on {ip}: {stderr_output}")
                        ssh.close()
                        return ip, private_ip, False

                    print(f"Retrying command: {command} (Attempt {attempt + 1})")
                    time.sleep(20) #Increase this from 10 to 20 seconds
                except Exception as e:
                    print(f"[Error] exec_command timeout or failure on {ip}: {e}")
                    ssh.close()
                    return ip, private_ip, False
                finally:
                    stdin.close()
                    stdout.close()
                    stderr.close()


```
The logs revealed that this is where the breakage is happening

the 450/0 and 450/25 logs had these in common:

1. SSH sessions silently closed mid-flight under swap pressure
   - Logs show `"Connecting to..."` but never reach `"Installing tomcat9"` or `"Command executed"` markers.
   - No stderr or stdout data captured; retry logic often abandoned after attempt 1.

2. Stdout `.read()` likely hanging under high memory contention
   - Some logs reach `exec_command()` but never print output.
   - Suspect stdout.read() blocks forever during swap thrash or socket timeout.

3. Thread starvation or eviction
   - Benchmarked logs indicate some processes never re-enter SSH logic after initial dispatch, likely OOM or preempted.

the 450/25 logs:(pooling)

- 40 install failures
- Failures clustered disproportionately in pooled phase (post-425), which coincides with kswapd0 peaking at >94% CPU.
- Several pooled tasks do not retry at all; thread reuse may be interfering with clean SSH state reinitialization.
- Average stdout/stderr logs shorter and less verbose than non-pooled set—likely preempted before reaching command execution.

the 450/0 logs: (no pooling)

- 32 install failures—slightly better despite higher total concurrency.
- Failures are more evenly distributed through the run.
- Swap usage sustained longer, but GitLab output more complete and retries appear to make deeper progress.



In summary based on forensics above: The susceptible areas of this code to severe system wide stress are in these particular areas:


- Silent exits when memory or I/O collapses mid-execution
- Retry logic short-circuited when `.read()` never returns
- Pooled threads possibly reusing unstable state or I/O handles under duress


The refactoring will include:
stdout watchdogs, verbose pre/post command markers, forced SSH reinit between tasks that wil be integrated into this code block.

In more detai:


1.Instrument stdout.read() with a watchdog or timeout guard
   - Example: spawn a timer thread or use select.select with socket timeout.
   - If `.read()` exceeds 20–30s, forcibly close the SSH client and reattempt.

2.Add log breadcrumbs before/after each SSH phase
   - A simple `logger.debug("Reached exec_command")`, `logger.debug("Reading stdout")`, etc., will help confirm exact failure locus.

3.Consider per-thread low-memory detection or early fallback
   - If memory dips below 5%, skip SSH attempt and queue for retry (log a memory-aware failure instead of silent one).

4.For pooled workers: forcibly recreate SSH client between tasks
   - Even if `ssh.close()` is called, recycled threads may retain unexpected state (thread-local buffers, dead sockets, etc.)

5.Track stdout/stderr output lengths
   - Flag if stdout is empty after command but no exception was raised—this often correlates with “ghost” executions.



Once these code changes are integrated into the aforementioned code block, the code will be far more resilient to host wide
system level severe stress.

Of course RAM and swap can always be increased to remediate the issues above, but the code needs to be have this resilience 
built into it as part of the design if memory on the host is constrained and if multi-processing is to be highly scaled.

The initial refactored code, SSH REFACTOR 1, is below:

```
# REFACTOR SSH 1:

        for command in commands:
            for attempt in range(3):
                try:
                    print(f"[DEBUG] Starting SSH command attempt {attempt + 1} on {ip}: {command}")

                    stdin, stdout, stderr = ssh.exec_command(command, timeout=60)

                    print(f"[DEBUG] Command sent: {command}")
                    print(f"[DEBUG] Waiting to read stdout...")
                    stdout_output = stdout.read().decode()
                    print(f"[DEBUG] Waiting to read stderr...")
                    stderr_output = stderr.read().decode()

                    print(f"[DEBUG] Read complete for {ip}")
                    print(f"[INFO] Executing command: {command}")
                    print(f"[INFO] STDOUT length: {len(stdout_output)} chars")
                    print(f"[INFO] STDERR length: {len(stderr_output)} chars")
                    print(f"STDOUT: {stdout_output}")
                    print(f"STDERR: {stderr_output}")

                    # Detect specific fatal Tomcat errors early
                    if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
                        print(f"[ERROR] Fatal: No install candidate on {ip}")
                        ssh.close()
                        return ip, private_ip, False

                    # Warning softener
                    if "WARNING:" in stderr_output:
                        print(f"[WARN] Non-fatal warning on {ip}: {stderr_output}")
                        stderr_output = ""

                    # Catch any remaining stderr (actual failures)
                    if stderr_output.strip():
                        print(f"[ERROR] Command error output on {ip}: {stderr_output}")
                        ssh.close()
                        return ip, private_ip, False

                    print(f"[DEBUG] Retrying command: {command} (Attempt {attempt + 1})")
                    time.sleep(20)

                except Exception as e:
                    print(f"[EXCEPTION] exec_command failed on {ip}: {e}")

                    # Log partial output if available
                    try:
                        if stdout:
                            stdout_output = stdout.read().decode()
                            print(f"[EXCEPTION DEBUG] Partial STDOUT ({len(stdout_output)}): {stdout_output}")
                        if stderr:
                            stderr_output = stderr.read().decode()
                            print(f"[EXCEPTION DEBUG] Partial STDERR ({len(stderr_output)}): {stderr_output}")
                    except Exception as inner:
                        print(f"[EXCEPTION] Error reading from stdout/stderr after failure: {inner}")

                    ssh.close()
                    return ip, private_ip, False

                finally:
                    if stdin: stdin.close()
                    if stdout: stdout.close()
                    if stderr: stderr.close()


```




## UPDATES: part 12: Hyper-scaling of processes (250, 400+ processes), benchmark testing and VPS swap tuning

The tests in part 11 below were preemptive. There are too many AWS idosyncratic issues that are clouding the comparisons.
When these issues are controlled the non-pooling seems to be better (higher concurrency) but the memory contention and thrashing
is much worse.

At 400-450 processes there is a clear pattern emerging.  Pooling does prevent the host 
VPS from locking up (especially the gitlab docker container) and relieves some of the memory (RAM and swap) contention
and memory thrashing, but there are consistently 
instances with missing installation of tomcat at this level. 
This is  not related to the AWS API contention as noted by the Retry in the gitlab
logs. These tests are still  well within the max retries of 15 (peak is 12). So even though this can cause a similar issue 
(failed tomcat9 instances) this is not the root cause at these higher levels of scaling

Correlating the process level logs and the gitlab console logs and the main() process orchestration logs there is a pattern of
the following with the failed EC2 tomcat instances (there is only one process per thread/tomcat SSH connection so this can
be cleanly correlated by the PID of the processes):

- SSH sessions stall post-authentication, failing to reach the command stage (these are missing `"Installing tomcat9"` or `"Command executed"`).
- Retry logic starts but never finishes, as thread workers get throttled or blocked waiting on stdout reads.
- Paramiko channels silently close, especially under socket buffer pressure or kernel-side TCP backlog overflows.
- Log writing fails to flush, especially if the container’s I/O thread queue is flooded (as GitLab metrics suggest).

The main area of failure is somewhere on the SSH connects in this heavily mutli-processed multi-threaded setup.

In short: SSH-related operations appear to be failing silently or stalling under heavy memory and swap pressure, particularly during the peak kswapd0 churn. Pooling may be exacerbating this by prolonging thread contention when swap is full and the container is I/O constrained.

This is a work in progress.

The RAM cannot be increased at this time, and the swap can be increased but will not be increased until I get to the root 
cause of these failures and implement the safeguards in the python module. This will result is a very resilient multi-processing
mult-threading code that can deal with severe host memory stress.

In addtion, holding off on the batch processing for the AWS API contention. The retry with exponential backoff os working ok 
for now, but at some point need to go to batch processing so that the Retries no longer have such a differential impact on 
pooling vs. nonpooling. That way we can compare the two scenarios in a more controlled setup. This is a work in progress, but
the premliminary code for API batch processing was introduced in part 10 below.




## UPDATES: part 11: Initial Key insights into process hyperscaling (150, 200, 250, 300, 400 concurrent processes) (more to follow)

The 250 concurrent process point for the current setup (16GB RAM and 16GB of swap) seems to be where the inflection point in the process scaling dynamics changes. At 200 process the pooling was a detriment to total execution time whereas the increased AWS API contention and swap dynamics at the 250 process level become poor enough where the 250 without pooling becomes the slower of the execution times, and pooling helps alleviate API contention and improve swap dynamics.  In testing the 250 and 0 pooled test execution time is improved upon with 25 pooled processes, and that is improved upon with the 50 pooled processes and that is improved upon with the 75 pooled processes, etc....   I did not see this behavior at the 200 concurrent process (pooling and increasing pooling resulted in poorer execution time).

At this point we introduce monitoring kswapd0 on the VPS (can’t do this from the python container as psutil does not allow direct access to process level host metrics, only global metrics on the VPS like CPU, RAM and swap).   The script below is run concurrently with the python pipeline to provide additiona metrics so that we can understand why the dynamics above begin to develop at the 250 inflection point. Here is the simple python script that is run directly on the VPS host. NOTE that the script is run in a python venv. I did not want to risk corrupting the native python installation on the VPS because the VPS requires that for configuration from the ansible controller (the VPS can be dynamically configured via ansible from the controller and the ansible on the controller (as the ansible client) requires a specific python version and python environment to continue to work)

The ptyhon code for kswapd0 logging in the module2 itself is still there but it is commented out. If running the module natively and not in a container that code will provide relaible kswapd0 logging in parallel wiht all of the other process orchestartion main() level logging and individual process logs as described in previous sections below.



```

(venv_kswapd) [root@vps ~]# cat kswapd_monitor.py 
import time
import psutil
import logging

# Set up logging
logging.basicConfig(filename="/root/kswapd_monitor.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def monitor_kswapd(interval=60):
    """Monitor kswapd0 every 'interval' seconds"""
    logging.info("Starting kswapd0 monitoring script...")
    
    while True:
        found = False
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
            if proc.info['name'] == "kswapd0":
                found = True
                logging.info(f"kswapd0 detected - PID: {proc.info['pid']}, CPU Usage: {proc.info['cpu_percent']}%")

        if not found:
            logging.warning("kswapd0 not found - it may not be actively swapping.")

        time.sleep(interval)

# Adjust the interval based on your testing needs
monitor_kswapd(interval=15)
```

Simply tail the logs during each pipeline run. We can correlate the python modules stats (CPU, swap and RAM, etc). with the kswapd0 tail logs via the timestamps very effectively. This permits us to ascertain the swap dynamics of each different test scenario run in the pipeline so that we can understand why pooling becomes effective at lowering execution time at the 250 process level and not at the 200 level.
Correlating the kswapd0 with the other python intrinsic logs is key.


### Review of releavant variables and Notation and examples:

desired_count is the intial batch of processes that will be handled by the multi-processing aspect of module 2 of the package where the core of the multi-theading and multi-processing optimizations were made

chunk_size it the chunk of IPs of EC2 instances which make up a chunk on which the multi-threading worker will process

max_workers is the thread count for the ThreadPoolExecutor which will work on the chunk of EC2 instance IPs of chunk_size
This thead count always pertains to a single process

From extensive testing it is best to set the max_workers to be equal to or greater than chunk_size (oversubsribing the thread worker does not increase execution time).  If max_workers is less than chunk_size performance and execution time degrades accordingly.

Examples: 

Example 1:
With a chunk of chunk_size 1 and 250 EC2 instances there will be 250 processes of 1 thread each to work on the 250 chunks of chunk_size=1

Note that for short hand moving forward with updates the following will be used, for example:
250/0 represents a test with 250 concurrent processes in the intial batch with 0 processes pooled
250/25 represents a test with 250 processes and in this case 250  EC2 instances, but inital batch is 225 processes and 25 are pooled and queued
250/50 represents a test with 250 processes and in this case 250 EC2 instances, but initial batch is 200 processes and 50 are pooled and queued


Example 2:
With a chunk_size of 2 and 400 EC2 instances there will be 200 processes of 2 threads each to work on the 200 chunks of chunk_size=2

200/0 represents a test with 200 concurrent processes in the intial batch with 0 processes pooled
200/25 represents a test with 200 processes and in this case 400 EC2 instances, but inital batch is 175 processes and 25 are pooled and queued
200/50 represents a test with 200 processes and in this case 400 EC2 instances, but initial batch is 150 processes and 50 are pooled and queued


NOTE:
The number of actual EC2 instances does not impact performance significantly as long as max_workers is set to equal or greater than the chunk_size, because the ThreadPoolExecutor is very efficient and is not the primary bottleneck in the process hyperscaling testing.
Thus there are many permutations available for testing given that the number of EC2 instances can always be changed to support a particular process concurrency test.  This can offer cost savings (for example to get 200 processes use a chunk_size of 1 and run it with 200 EC2 instances rather than 200 processes with a chunk_size of 2 with 400 EC2 instances.



### AWS API contention and exponential backoff with jitter for retrying API calls:

For API contention with the security group rule assignments (call to AuthorizeSecurityGroupIngress by authorize_security_group_ingress method)
 the max_retries is a siginficant variable

This needs to be set to 10 for the higher process level tests because the number of retries often exceeds 5.  It can be increased to
whatever number is necessary to support the number of  processes and in general higher process concurrency requires a higer 
max_retries number. This is ok for the exponential backoff python code because the delay parameter is not changed at all and only
the retries is changed for these higher process level tests. This ensures that the higher pooling test (less concurrent processes)
are not unecessarily penalized (wth an increased delay parameter) when comparted to a non-pooling test in regards to API contention.
If a higher concurrency is required it is intrinsically penalized because it will initiate and require more retries, whereas
the lower pooled tests will not require additional retries to the degree that fully concurrent tests do. This controls the 
tests when comparing pooled vs. non-pooled testing.

AWS recommends this exponential backoff, but a batch approach can also be considered as well. The max_retries simple solution below seems to be accomodating the higher process scaling well, and a batch approach will be considered if the number of retries becomes unruly for the hyper-scaling testing (400 and 800 processes).  With a batch approach we can essentially throttle and stagger the API requests (security group rule updates to each of the EC2 instances) into batches, batching the updates outside of the thread woker processing.

Note that for now the SG is the default SG and that can be chnaged in module1 of this python package.

random.uniform(0, 1) adds randomness (a jitter)  to prevent synchronized retries among multiple instances.

Randomness factors have been added throughout the python module, most notably for the process level logging so that we don't get storms of logging data fetches across all the parallel processes, or in this case a retry storm on the EC2 instance security group configuratino.  The random.uniform is the jitter addtion to the base exponential backoff.
((The logging was interesting. Prior to using randomness the logging was causing a deteriorition in the execution time (more on the process level logging is in the UPDATE main() logging  section below))

Without this, all retries could occur at the same exact intervals, causing a potential "retry storm.




```
def retry_with_backoff(func, max_retries=10, base_delay=1, max_delay=10, *args, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for AWS API call.")

```

This function above is used to wrap all the python calls to the authorize_security_group_ingress boto3 method that applies the SG 
rule to the SG (default for now) that is attached to each of the EC2 instances. The multi-processing and multi-threading
of this, makes this a requiremennt. Otherwise I see failed tomcat9 installatinons when the API is overwhelmed.

 Here is an example of the wrap for port 22 SSH rule applied to the default SG that is used on all the EC2 instances:


```
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
```
This is working really well especially at the higher scale levels and the gitlab console logs can easily be searched for 
"Retry <seconds>" to ascertain the degree of API contention that is encountered by the script.



### Batch processing to deal with the API contention issue above:

I am going to leave in the current implementation with the exponential backoff and jitter becasue it is introducing an AWS delay 
factor that makes testing the tradeoffs between pooling the processes and not pooling the processes easy to demonstrate. The retries will penalize the non-pooled tests accordingly and this can be used as a general indicator of too much process contention causing a delay with AWS roll out.


The AWS limits are per account and not per request, so batching them together will distribute the load more evenly rather than massive API spikes encountered without the batch processing.

At a later stage the API contention issue will be approched using the batch processing with a worker thread as indicated below:
There are a lot of variants to this approach:


#### Method 1: Standard batch processing with a queue + a single background worker thread:

This appraoch uses a batch based upon a standard interval (2 seconds in this case), but can be optimized as shown further below, in case a static 2 second approach will not hold up with very high parallel process scenarios.

Each process in the current configuration creates 3 API requests with the authorize_seucrity_group_ingress method, one for port 22
one for port 80 and one for port 8080. This is designed this way so that it is extensible in the future for per process security
group rule customization (each process handles the chunk of chunk_size IPs and they will have similar rules in the security group)

Example of the batch processing: with 250 processes, and 3 rules to be configured in the security group, that is 750 API calls.
The worker thread will check the update_queue every 2 seconds, IF it is not working on anything. If it is
working on a batch it will have to complete the current batch, and then it will check and rab whatever is in the update_queue
since it last checked.  The for loop in the function causes this problem. It won't exit until all of the current batch is complete
and that leads to non-deterministic behavior.

This simple batch processing is prone to congestion because the batch sizes are not deterministic and the process timing for each
batch can get to be very high if a large accumulation occurs in the update_queue between worker thread processing.
In this way it is still prone to API congestion.

A solution is Method 2 below:  limiting batch size & adjusting the batch interval dynamically can help smooth out execution time and prevent request backlogs.  


```
import threading
import time

# Create the queue
update_queue = []
lock = threading.Lock()

def batch_security_group_updates():
    while True:
        time.sleep(2)  # Flush interval
        with lock:
            if update_queue:
                print(f"Processing {len(update_queue)} security group updates...")
                for sg_update in update_queue:
                    try:
                        my_ec2.authorize_security_group_ingress(**sg_update)
                    except my_ec2.exceptions.ClientError as e:
                        if 'InvalidPermission.Duplicate' in str(e):
                            print(f"Rule already exists for {sg_update['GroupId']}")
                        else:
                            raise
                update_queue.clear()  # Reset after processing




# Start worker thread
threading.Thread(target=batch_security_group_updates, daemon=True).start()


# Update the queue with the latest/current security group requests when the processes add rules to the SG(see example below)
def queue_security_group_update(GroupId, IpPermissions):
    with lock:
        update_queue.append({'GroupId': GroupId, 'IpPermissions': IpPermissions})




# Example usage:
for sg_id in set(security_group_ids):
    queue_security_group_update(sg_id, [{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }])
```

update_queue(Global List)  
   - Stores pending security group rule update requests form the parallel process rule configurations. This is a list of requests
that have  not actually been called using authorize_security_group_ingress
   - Updates accumulate here before they are processed in batches by the worker thread
   - Need the mutex (`lock`): ensures thread safety when worker thread is accessing the queue.

batch_security_group_updates() This is the Worker Thread  
   - This background thread constantly runs and checks for queued security group rule API request updates in update_queue  
   - If it is "stuck" processing a large batch of requests, it will be longer than 2 seconds before it grabs the next items from
the update_queue. This is the main drawback of this method. Batches can be highly variable and grow to large sizes.
   - Updates are applied via `my_ec2.authorize_security_group_ingress(**sg_update)`.  This actually updates the security group with the rules (in this case 22, 80 and 8080). This is done per process, hence the API congestion of accumulated API requests.
   - After processing, the queue is cleared, making room for new updates.  The queue has to completely clear prior to getting the new batch from the current update_queue.

queue_security_group_update() This actually Adds  Requests to Queue that will need worker thread to process
   - This function adds new requests to the queue.  This is done at the per process level. So the queue could grow very quickly and
non-uniformly 
   - The lock ensures multiple processes don’t corrupt the queue while adding updates.  
   - Allows different security groups to be queued dynamically.





#### Method 2: Adaptive solution for batch processing: Dynamic batch intervals to prevent request pile-up AND Batch size limits to ensure AWS requests don’t spike all at once.

This resolves any of the shortcomings of method 1 above which is still prone to API congestion.

The functions basically still work as described in method1 but there are several enhancements to reduce batch API congestion:

MAX_BATCH_SIZE and NUM_WORKERS can be adjusted to accomodate process scaling needs. 

```
import threading
import time

update_queue = []
lock = threading.Lock()
MAX_BATCH_SIZE = 50  # Limits number of requests processed in a single batch
base_interval = 2  # Initial interval, dynamically adjusted

def batch_security_group_updates():
    global base_interval

    while True:
        time.sleep(base_interval)  # Wait before checking the queue

        with lock:
            batch = update_queue[:MAX_BATCH_SIZE]  # Grab at most 50 requests
            update_queue[:] = update_queue[MAX_BATCH_SIZE:]  # Remove processed requests

        start_time = time.time()
        for sg_update in batch:
            try:
                my_ec2.authorize_security_group_ingress(**sg_update)
            except my_ec2.exceptions.ClientError as e:
                if 'InvalidPermission.Duplicate' in str(e):
                    print(f"Rule already exists for {sg_update['GroupId']}")
                else:
                    raise

        elapsed_time = time.time() - start_time
        base_interval = min(5, max(2, elapsed_time * 1.5))  # Dynamically adjust interval

        print(f"Next batch interval set to {base_interval:.2f} seconds")



# Start multiple worker threads
NUM_WORKERS = 4  # Adjust based on expected load
for _ in range(NUM_WORKERS):
    threading.Thread(target=batch_security_group_updates, daemon=True).start()



def queue_security_group_update(GroupId, IpPermissions):
    with lock:
        update_queue.append({'GroupId': GroupId, 'IpPermissions': IpPermissions})


# Example usage:
for sg_id in set(security_group_ids):
    queue_security_group_update(sg_id, [{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }])
```









### General test metrics and test setup for hyper-scaling of processes:

As will be shown, some of the major factors and metrics to monitor are the RAM, swap, CPU, kswapd0, the API contention through the Retry counts in the gitlab pipeline logs. Always ensure that all the instances have successful installations of tomcat9 using a search of "Instalation completed" in the gitlab pipeline console logs.
Also alway make sure to clear the swap on the VPS prior to each test, although testing revealed that this did not impact successive tests when the swap was NOT cleared. Swap can easily be cleared by using this command below in the VPS SSH session:

sudo swapoff -a && sudo swapon -a






### gitlab optimizations:

All of the python testing is done in a pipeline for ease of managment, and quick turnaround and isolation from the main VPS OS.

There have been several things that needed to be optimized with the gitlab docker container that is running the pipeline for the docker container that runs the python code.

The first was that the log capacity had to be increased several times. The per process logging and the console messages for each EC2 instance consumes large amounts of gitlab console logs. This can be increased on a self-hosted gitlab instance like this but not on the public instances. 

The second item was the clearing of the gitlab docker container registry artifacts. Since my gitlab instance is running on a docker container on the VPS use the script below to identify the container id and then docker exec into the container and run the gitlab-ctl registry-garbage-collect periodically. I will incorporate this as a cronjob on the VPS at a later date. The simple shell script is below:

```
[root@vps ~]# cat gitlab_cleanup.sh 
   #!/bin/bash
   CONTAINER_ID=$(docker ps --filter "name=gitlab" --format "{{.ID}}")
   
   if [ -n "$CONTAINER_ID" ]; then
       docker exec -it "$CONTAINER_ID" gitlab-ctl registry-garbage-collect
   else
       echo "No running GitLab container found."
   fi
```





## UPDATES: BENCHMARKING: part 10: main() process and process pooling orchestration level logging infra

This has the main() level logging infra for process level and process pooling orchestration level data.  This is not per process and thread logging. See part 8 below for that.

There are now two main() logging helper functions as shown below.   This was to make the main() process orchestration loggin
more adaptable and extensible in terms of adding new metrics
Per core CPU measurements will need to be added at higher process concurrency levels
All of the other memory based metrics are listed below: RAM, free RAM, and swap usage.  The system has a fixed 16 GB of RAM
The swap has been methodically increased and is now at 16GB in prep for the hyper-scaling
Other enhancements are a radomized inter-test sampling and also some static samplings during test stress (for now at 50% and
75% of a baseline execution time of 10 minutes.
Another enhancement is that the inter-test samples are done with independent but concurrent background threads. The 
multi-threading logic has been pulled out of main() and put into the second helper function below that returns a list
of all the threads to main() . That way the threads can be .join'ed in main() to make sure that the inter-test data is 
completely fetched prior to main(0 flush and cleanup.
Helper function 2 calls helper function 1 for the specific logging semantics that can be used across all of the various 
timing threads. The logging is fully asynchronous so the performance of main() execution code (multi-processing and pooling)
is not affected. This makes the code more performance resilient with the logging overhead.

Helper function 0 is very similar to the process level logging setup_logging() function, except this creates a dedicates
main() log file in the archive directory of the gitlab pipeline as describe below. It is important to call this function early
on in main()



### main() logging helper functions: 

helper function 0:

```
#### ADD the main() level process and process pooling orchestration logging level code. The setup helper function is below
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

    return logger
```



helper function 1:

```
## (helper logging function) this is for inter-test process orchestration level memory stats.
## What i have done is modularize the threading of these operations into a second function that follows(see below
## this function).
## This function is for the actual logging semantics and output structure
def sample_inter_test_metrics(logger, delay, label):
    """Samples memory and CPU metrics at specific points during execution."""
    time.sleep(delay)  # Wait for the specified timing

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    #cpu_usage = psutil.cpu_percent(interval=None, percpu=True)

    cpu_usage = psutil.cpu_percent(interval=1, percpu=True)

    logger.info(f"[MAIN] {label} Inter-test RAM Usage: {mem.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Free Memory: {mem.available / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Swap Usage: {swap.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test CPU Usage (per-core): {cpu_usage}")

```

helper function 2:


```
## (helper logging function) call this function in the middle of the logging in main() to create the list of independent 
## threads in the background for each thread log timing variant
## The objective is to collect load bearing memory and CPU stats for the hyper-scaling tests
## moving the threading.Thread method outside of main() makes this much more extensible in case I need to add more
## static or dynamic sampling points!!
## NOTE: i forgot to add the thread storage so that we can wait for them to complete in main with .join! It is working now.


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
```



### main() logging changes:

These are the added logging portions to the main() function using the helper functions above. 
This will help at a higher level when we optimize the desired_count relative to RAM VPS usage for hyper-scaling the process number
count. This took several iterations to get to work. The main initial problem was that the execution time portion was not getting 
written to disk and was missing in the main() level log. The fsync stream handler resolved this issue. Other issues were resolved
with the helper functions 1 and 2 above.

The edited out areas of the main() are noted below to save space.


```
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


<<EDITED OUT>>



### Configurable parameters
    chunk_size = 2     # Number of IPs per process
    max_workers = 2       # Threads per process
    desired_count = 150     # Max concurrent processes

    chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]


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



<<EDITED OUT. The block below ends with the call to the helper function 2 above start_inter_test_logging>>



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

    start_time = time.time()

    ##### CORE CALL TO THE WORKER THREADS tomcat_worker_wrapper. Wrapped for the process level logging!! ####
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
    finally:
        total_time = time.time() - start_time
        logger.info("[MAIN] All chunks have been processed.")
        logger.info(f"[MAIN] Total execution time for all chunks of chunk_size: {total_time:.2f} seconds")

        # Ensure the inter-test metrics thread that were started in start_inter_test_logging completes before exiting
        # At this point we have the inter-test log information captured!!!
        # Ensure ALL inter-test logging threads assinged to "inter_test_threads" (the list of threads returned from
        # the function, finish before cleanup)
        for thread in inter_test_threads:
            thread.join()


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

```


The stream handler will forward the logging info to both the gilab pipeline console and the archive directory on the
gitlab pipeline. The main() function will log to its own log file in the artifacts separate from process level log
files by design.
With moderate level number of processes (100-150) this logging is performing welll and I did not notice any added
total execution time for this module.


Example of content saved to the main log file:

Added in Swap, Free RAM memory and RAM usage statistics. These will be the main bottlenecks moving forward with
the process hyperscaling of 200, 300 and 400 processes.  Desired_count adjustments for the number of pooled
processes will be the main way to deal with the memory issues that will be encountered.  The trade off is that
process queue pooling is inherently slower in terms of concurrency and parallelization, but it will be necessary
if RAM is a constant on the VPS controller.

Added inter-test sampling as well as shown below. This has been very helpful in assessing relative performance when 
changing the desired_count.

```
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Total processes: 150
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Initial batch (desired_count): 150
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Remaining processes to pool: 0
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Number of batches of the pooled processes. This is the *additional waves of processes that will be needed after the initial batch (`desired_count`) to complete all the work: 0
2025-05-30 04:18:48,643 - 8 - INFO - [MAIN] Initial RAM Usage: 11854.68 MB
2025-05-30 04:18:48,643 - 8 - INFO - [MAIN] Initial Free Memory: 3380.49 MB
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Initial Swap Usage: 0.00 MB
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Initial CPU Usage (per-core): [1.0, 0.0, 1.0, 1.0, 0.0, 0.0]
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Starting multiprocessing pool...
2025-05-30 04:22:05,149 - 8 - INFO - [MAIN] Random 30/70 Inter-test RAM Usage: 14277.98 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test Free Memory: 1227.14 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test Swap Usage: 5022.49 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test CPU Usage (per-core): [8.1, 6.9, 6.1, 5.1, 7.1, 8.0]
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test RAM Usage: 14216.60 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test Free Memory: 1287.11 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test Swap Usage: 5009.99 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test CPU Usage (per-core): [9.3, 9.1, 10.8, 7.1, 8.1, 12.1]
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test RAM Usage: 14165.88 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test Free Memory: 1332.91 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test Swap Usage: 5223.87 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test CPU Usage (per-core): [5.9, 6.1, 4.0, 6.1, 5.9, 4.0]
2025-05-30 04:28:45,264 - 8 - INFO - [MAIN] All chunks have been processed.
2025-05-30 04:28:45,264 - 8 - INFO - [MAIN] Total execution time for all chunks of chunk_size: 596.62 seconds
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final RAM Usage: 8217.49 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final Free Memory: 7279.59 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final Swap Usage: 5256.36 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final CPU Usage (per-core): [13.2, 13.0, 14.2, 13.7, 13.0, 13.0]


```
Early tests are revealing an interesting tradeoff with the increased parallelization of processes when desired_count is
raised up higher and eventually set at max (pooling is turned off). 

With process pooling the swap usage is in general lower due to less concurrency. 

With process pooling turned off (desired_count = total number of processes), the swap usage is 
higher.   

Thus the VPS is under more stress with pooling turned off. 

The downside of running with pooling is that the total execution time is notably slower. 

So moving forward with higher process counts there will have to be a trade off in this fashion and because RAM is affected as
well, at some point the process pooling will be mandatory.

There have been several instances where the VPS freezes up and this is because of VPS contentions issues.

NOTE: it is really important to clear the swap between tests because cleanup is not always complete prior to starting the 
next test. The swap can be cleared on the VPS with: sudo swapoff -a && sudo swapon -a

There was also an interesting issue with CPU core3 on the VPS with process pooling test but not with the test without 
pooling. This will required more testing and investigation. The CPU cores may be differentially affected with pooling vs.
no pooling scenarios.






## UPDATES: BENCHMARKING: part 9: exponential backoff on the authorize_security_group_ingress

Hitting the AWS API limit on the calls to this function with parallel desired_count of 45 on the processes.
Wrap the authorize_security_group_ingress in a wrapper function with exponential backoff retry_with_backoff.
This resolved the 45 desired_count issue and will move up the scaling to higher desired_count on the multi-processing.
The installation time has decreased from 23:50 mintues with desired_count of 30 to 16 mintues with desired_count of 45. Very large improvement.

This error would manifest itself as aborted scripts and failed tomcat9 installations to many of the EC2 instances. This is  no longer happening even at higher scale levels and higher desired_count levels.


The setup consists of 250 EC instances, chunk_size of 2 for 125 processes and max_workers= 2 threads per process.

Two pools are now being created, the one of 45 and then the queued pool of processes of 80

The wrapper function is below:
```
def retry_with_backoff(func, max_retries=5, base_delay=1, max_delay=10, *args, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for AWS API call.")
```




The exponential backoff is being used extensively as shown in the gitlab pipeline console logs:

[Retry 1] RequestLimitExceeded. Retrying in 1.86s...
[Retry 1] RequestLimitExceeded. Retrying in 1.82s...
[Retry 1] RequestLimitExceeded. Retrying in 1.04s...
[Retry 1] RequestLimitExceeded. Retrying in 1.53s...
[Retry 1] RequestLimitExceeded. Retrying in 1.87s...
[Retry 1] RequestLimitExceeded. Retrying in 1.97s...
[Retry 1] RequestLimitExceeded. Retrying in 1.67s...
[Retry 1] RequestLimitExceeded. Retrying in 1.89s...


At 70 desired_count, the CPU is getting a bit more taxed, down to 70-80% idle but the pipeline completed wihtout errors 
and all 250 instances are installed with tomcat9
swap is stable as well
The logging infra solid as well as the random sampling of processes in the process group
1 log file per process
Execution time is improving massively:  Record time 12:48 with 70, 23:50 with 30 desired_count and 16:08 with 45 desired count

At 100 desired_count, swap stable at about 5GB of usage.
There is still improvement in exeuction time but diminishing returns:
Record time 12:25 with 100,  12:48 with 70, 23:50 with 30 desired_count and 16:08 with 45 desired count
No missed installations
Logging infra is solid
1 log file per process


At 125 desired_count, this effectively disabled process pooling and it will try to run this without any pooling queue for the processes. The CPU will be taxed more.
In this run the RAM is starting to get high. About 12.9GB used of the 16GB. At hyper-scaling levels of 300 or 400 if this becomes a problem then the pooling will definitely help.   The process pooling entire purpose is for hyper-scaling at these levels.
Record time is 10:24 a large improvement over the 100 desired_count.  Massive improvments over the original setup as well
No missed installations (all 250/250)
Logging infra is solid
1 log file per process
swap is stable at 5 GB.

Execution time summary is below:
desired_count   execution time in minutes:seconds

```
30 → 23:50
45 → 16:08
70 → 12:48
100 → 12:25
125 → 10:24
```


So process pooling for these lower process count levels is slowing the process down and we do not need it.

At the higher hyper-scaling process levels the process pooling will come in useful especially in regards to the 
VPS RAM utilization.





## UPDATES: BENCHMARKING part 8: Multi-processing logging for the pooled/queued processes as well. 

The new code additions are below and will produce logs for the pooled processes as well now:

### Phase 1:
```
## The various models for the per process logging are further down below. With model4 there is still an issue with
## multi-processing pooling whereby the queued processes(pooled) are not getting a log file. This is because of
## process re-use by the multiprocessing pooler. The fix involves:
# Wrap the tomcat_worker and use the wrap function tomcat_worker from the main() call to tomcat_worker as tomcat_worker_wrapper
# - `tomcat_worker_wrapper()` is called **for every task**, even if the process is reused.
# - `setup_logging()` is guaranteed to run at the start of each task, ensuring a fresh log file is created for each process execution.
# - Since using `force=True` in `basicConfig()`, it will override any previous logging config in that process.

def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
    setup_logging()  # Ensure logging is reconfigured for each task
    return tomcat_worker(instance_info, security_group_ids, max_workers)
```


```
## and in main()
    # wrap the tomcat_worker in the tomcat_worker_wrapper function (defined at top of file as helper) to fix
    # the problem with the pooled/queued processes not getting their own log file for the multi-processing logging
    # code
    with multiprocessing.Pool(processes=desired_count) as pool:
        pool.starmap(tomcat_worker_wrapper, args_list)
```


### Phase 2:

With this change the log files are now being created but the PID is being reused from the original desired_count set, for the pooled processes. To fix this incorporate the uuid into the name of the log files so that they are no longer overwritting the original process logs with the pooled log that is using the same PID. In this was there will be unique log files for the original process set and all the pooled processes. The updated code is below


```
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
```

### Phase 3:

Getting empty log files with the phase 2 changes. Two options: Switch from a basicConfig logger to a stream handler that is ideally
suited for multi-processing and per process logging infrastructure when there is pooling and pid reuse of the processes
This is a complex patch and had some issues.   Option2 is much easier: just remove the second call to setup_logging() in
the tomcat_worker() now that tomcat_worker_wrapper() calls tomcat_worker() and has the setup_logging() call in it (in
the wrapper function). No need to call it twice. Also added thread name to the setup_logging() function as shown above.


The code is now reliably logging 1 log file per process regardless of process type (pooled or non-pooled) and also creates an aggregate log file with all the log files in one file.




## UPDATES: BENCHMARKING part 7: Advanced logging implementation to collect per process CPU, swap memory, etc during the benchmarking tests


The 50 process and 75 process and the 100 process ran fine with the multi-processing pooling and desired_count of 25 (this will be adjusted shortly to optimize). There was no CPU contention or swap memory issues as expected due to the queuing of the test of the processes >25. As expected the time to compelte increased (not linearly).  The 34 process prior took about 8:50 minutes, the 75 process took about 13:20 minutes and the 100 process about 15 minutes.

Next, logging was implemented at the per process level. This involved a lot of code additions, as the setup_logging function needs to be run inside the tomcat_worker prior to running the multi-threading TreadPoolExecutor. There are several functions that are used to accomplish this and the logging is pulled from a mount on the docker container that is running the python script to the mount on the workspace on the gitlab pipeline.   Once this is done the artifacts are pulled into the pipeline and can be easily viewed. The per file process log files are also aggregated into a consolidated file for easy viewing. An example of the per process logging is below:

A key part to getting this to work in multi-processing environment is to use the force below to allow per process logging that is not natively supported in the basic logger.

```
def setup_logging():
    pid = multiprocessing.current_process().pid
    log_path = f'/aws_EC2/logs/benchmark_{pid}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # Remove any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(process)d - %(message)s',
        force=True  # Python 3.8+ only
    )
```

Sample log output per process is below from the consolidated file:


```
===== logs/benchmark_10.log =====
2025-05-23 21:44:43,694 - 10 - Logging initialized in process.
2025-05-23 21:44:43,694 - 10 - Test log entry to ensure file is created.
2025-05-23 21:44:46,634 - 10 - [PID 10] START: Tomcat Installation Threaded
2025-05-23 21:44:46,635 - 10 - [PID 10] Initial swap usage: 3.51 GB
2025-05-23 21:44:46,635 - 10 - [PID 10] Initial CPU usage: 0.00%
2025-05-23 21:46:48,880 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,892 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,899 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:49,339 - 10 - Authentication (publickey) successful!
2025-05-23 21:46:49,366 - 10 - Authentication (publickey) successful!
2025-05-23 21:46:49,372 - 10 - Authentication (publickey) successful!
2025-05-23 21:47:49,812 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:50,258 - 10 - Authentication (publickey) successful!
2025-05-23 21:53:33,827 - 10 - [PID 10] END: Tomcat Installation Threaded
2025-05-23 21:53:33,827 - 10 - [PID 10] Final swap usage: 3.51 GB
2025-05-23 21:53:33,827 - 10 - [PID 10] Final CPU usage: 0.00%
2025-05-23 21:53:33,827 - 10 - [PID 10] Total runtime: 527.19 seconds
```



```
===== logs/benchmark_11.log =====
2025-05-23 21:44:43,694 - 11 - Logging initialized in process.
2025-05-23 21:44:43,694 - 11 - Test log entry to ensure file is created.
2025-05-23 21:44:46,539 - 11 - [PID 11] START: Tomcat Installation Threaded
2025-05-23 21:44:46,539 - 11 - [PID 11] Initial swap usage: 3.51 GB
2025-05-23 21:44:46,539 - 11 - [PID 11] Initial CPU usage: 0.00%
2025-05-23 21:46:48,658 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,673 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:49,099 - 11 - Authentication (publickey) successful!
2025-05-23 21:46:49,136 - 11 - Authentication (publickey) successful!
2025-05-23 21:47:49,427 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:49,449 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:49,872 - 11 - Authentication (publickey) successful!
2025-05-23 21:47:49,914 - 11 - Authentication (publickey) successful!
2025-05-23 21:53:50,175 - 11 - [PID 11] END: Tomcat Installation Threaded
2025-05-23 21:53:50,175 - 11 - [PID 11] Final swap usage: 3.51 GB
2025-05-23 21:53:50,175 - 11 - [PID 11] Final CPU usage: 0.00%
2025-05-23 21:53:50,175 - 11 - [PID 11] Total runtime: 543.64 seconds
```




This was enhanced with a periodic sampler for CPU and swap memory to the output below (sampling rate of 60 seconds default), but as shown this had a noticable drag on the total runtime of about 50-150 seconds:

```
===== logs/benchmark_10.log =====
2025-05-23 23:53:07,972 - 10 - Logging initialized in process.
2025-05-23 23:53:07,973 - 10 - Test log entry to ensure file is created.
2025-05-23 23:53:10,665 - 10 - [PID 10] START: Tomcat Installation Threaded
2025-05-23 23:53:10,665 - 10 - [PID 10] Initial swap usage: 3.47 GB
2025-05-23 23:53:10,665 - 10 - [PID 10] Initial CPU usage: 0.00%
2025-05-23 23:53:10,670 - 10 - [PID 10] Sampled CPU usage: 0.00%
2025-05-23 23:53:10,670 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:54:10,671 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-23 23:54:10,671 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:54:52,722 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:52,796 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:52,828 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:53,550 - 10 - Authentication (publickey) successful!
2025-05-23 23:54:53,678 - 10 - Authentication (publickey) successful!
2025-05-23 23:54:53,825 - 10 - Authentication (publickey) successful!
2025-05-23 23:55:10,671 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-23 23:55:10,671 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:55:53,264 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:55:53,710 - 10 - Authentication (publickey) successful!
2025-05-23 23:56:10,678 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:56:10,678 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:57:10,679 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-23 23:57:10,679 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:58:10,679 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:58:10,680 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:59:10,680 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:59:10,680 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:00:10,681 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-24 00:00:10,681 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:01:10,681 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-24 00:01:10,681 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:02:10,682 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-24 00:02:10,682 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:02:59,123 - 10 - [PID 10] END: Tomcat Installation Threaded
2025-05-24 00:02:59,123 - 10 - [PID 10] Final swap usage: 3.47 GB
2025-05-24 00:02:59,123 - 10 - [PID 10] Final CPU usage: 0.00%
2025-05-24 00:02:59,123 - 10 - [PID 10] Total runtime: 588.46 seconds
```



This logging will be used to access performance with the hyper-scaling cases of multi-processing when the desired_count ismehthodically increased.


Model 1: Mult-process logging without sampling

```
@contextmanager
def benchmark(test_name):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    yield

    end_time = time.time()
    end_swap = psutil.swap_memory().used / (1024 ** 3)
    end_cpu = process.cpu_percent(interval=1)

    logging.info(f"[PID {pid}] END: {test_name}")
    logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
    logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
    logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

def run_test(test_name, func, *args, **kwargs):
    with benchmark(test_name):
        func(*args, **kwargs)
```







Model 2: Multi-process logging with the basic sample code determinisic with fixed interval. 
This produced a drag on completion time for all of the processes due to sample collisions between the processes
Writing to a shared mount (docker mount to gitlab workspace) also made the issue worse.
The sampler code is shown below:


```
def sample_metrics(stop_event, pid, interval):
    process = psutil.Process()
    while not stop_event.is_set():
        cpu = process.cpu_percent(interval=None)
        swap = psutil.swap_memory().used / (1024 ** 3)
        logging.info(f"[PID {pid}] Sampled CPU usage: {cpu:.2f}%")
        logging.info(f"[PID {pid}] Sampled swap usage: {swap:.2f} GB")
        stop_event.wait(interval)
@contextmanager
def benchmark(test_name, sample_interval=60):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    stop_event = threading.Event()
    sampler_thread = threading.Thread(target=sample_metrics, args=(stop_event, pid, sample_interval))
    sampler_thread.start()

    try:
        yield
    finally:
       stop_event.set()
        sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)

        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

# set the sample_interval here. Default is 60 seconds
def run_test(test_name, func, *args, sample_interval=60, **kwargs):
    with benchmark(test_name, sample_interval=sample_interval):
        func(*args, **kwargs)
```





Model 3 of the sampler: randomize a period of 50 to 250 seconds in which to take a single sample per process. This will minimize the probability of sample collisions that were slowing down the runtime of the tests.  The modified code is below:
This still had poor performance. 

```
import random
def sample_metrics_once_after_random_delay(pid, delay):
    time.sleep(delay)
    process = psutil.Process()
    cpu = process.cpu_percent(interval=None)
    swap = psutil.swap_memory().used / (1024 ** 3)
    logging.info(f"[PID {pid}] Random-sample CPU usage: {cpu:.2f}% after {delay:.1f}s")
    logging.info(f"[PID {pid}] Random-sample swap usage: {swap:.2f} GB")

@contextmanager
def benchmark(test_name, sample_delay):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    sampler_thread = threading.Thread(
        target=sample_metrics_once_after_random_delay,
        args=(pid, sample_delay)
    )
    sampler_thread.start()

    try:
        yield
   finally:
        sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)

        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")

        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, **kwargs):
    delay = random.uniform(min_sample_delay, max_sample_delay)
    with benchmark(test_name, sample_delay=delay):
        func(*args, **kwargs)
```


Model 4 of the sampler: Combine the randomizer with a randomizer on the processes to sample (10% sample over time)
This appears to have resolved the sampling contention and will be used for the process hyper-scaling.

Randomize the process in which to sample and also randomize when that random sample is taken during the execution time. This minimizes logging contention when processes are massivvely scaled and has been tested for such.

The benefits are:

Selective sampling: Only a random 10% of processes log detailed metrics, which avoids overwhelming the disk and CPU.

The 10% probability is configurable

Randomized delay: Prevents log spikes and contention by staggering when metrics are collected.

The randomized delay interval is also configurable. It is based upon typical large scale process execution times for this particular python module

Thread-safe sampling: The sampler runs in a separate thread and joins cleanly, ensuring no orphaned threads.

Context-managed benchmarking: Clean start/end logging with CPU and swap usage, wrapped around any function.


Here is the revised code:

```
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

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):
    delay = None
    if random.random() < sample_probability:
        delay = random.uniform(min_sample_delay, max_sample_delay)

    with benchmark(test_name, sample_delay=delay):
        func(*args, **kwargs)
```



## UPDATES: BENCHMARKING part 6: testing the multi-processing hyper-scaling with the pooling code

Initial tests look very good. The problematic process count > 25 where there were installation failures is not occuring withe process pooling. 

Tested 200 instances with chunk_size of 6 for 34 processes and it went well.
Swap was almost exhausted at nearly 4GB so increase swap to 8 GB for futher testing below.
This test took longer than the baseline non-pooled of 6:30 minutes at about 8:50 minutes but that is expected as there are 9 processes in the queue that need to wait to be processed over the desired_count limit of 25

The CPU was fairly stable at an average of 70% on the VPS controller. 

Planned further testing:
Using a chunk_size of 4 and max_workers of 4 run the following tests

- 200 instances → 50 processes
- 300 → 75
- 400 → 100

Decrease chunk_size to 2 and run the following test:
- 250 → 125
- 300 → 150
- 400 → 200

Note use the t2.small since the AWS limit is at 402 vCPUs


There are a variety of things that will be monitored dudring these test on the VPS and they will be added to this README as the testing progresses.

The code is all checked in at this time for this module2.






## UPDATES: BENCHMARKING part5: 

Sanity testing of 200 and 400 instances

200 instances with 10 chunk size and 10 threads for 20 processes ran fine. All instances have tomcat installed. So the issue is clearly with the number of processes < 25 and not number of instances, or SSH connections, etc.

400 instances with 20 chunk and 20 threads also running. Had to increase gitlab runner log capacity from 10 MB to 50 MB. TThis worked as well confirming that it is the  number of processes and nothing else. 

The increase in swap from 1GB to 4GB will help the VPS when scaling to 100+ processes as the python code is refactored to support this hyper-scaling corner case.


### Code refactoring to deal with the process hyper-scaling issue > 25:

1. Introduce a process pool or task queue model
2. Add centralized logging and error handling
3. Ensure failed installations are always reported. Currently the Installation succeeded on is working but the Installation failed is falling through, and it is not catching when the process overload causes failed tomcat9 installations on some of the instances
4. Optionally add a post-run audit summary


REFACTORED main() to support multi-processing with pooling to deal with hyperscaling case
 note that this is still based upon Model 2 from the original main() below that does not have the pooling with
 the multiprocessing

 with model 2: each process handles chunk_size of IPs with max_workers number of threads. Any extra IPs use
 an additional process.

 This main() uses the tomcat_worker rather than the original install_tomcat_on_instances used in the main() 
 without pooling.   The tomcat_worker permits pickling by main().   

 The pooling will start the desired_count of concurrent processes (25 has been tested for error free)
 The rest of the processes will be initiated as the original 25 finish up their tasks and exit, one by one
 with multiprocessing.Pool(processes=desired_count) as pool:
 from extensive testing it is recommended to keep desired_count to 25 for this pariticular setup

 The chunk_size is the number of IPs (dictionary list) assigned per process

 max_workers is the number of threads in the ThreadPoolExecutor to use to parallel process the SSH connections for
 the chunk dictionary list of IPs.  

 chunk_size should always be less than or equal to max_workers. If oversubscribing max_workers performance degrades
 very raplidly.  Unused threads (undersubscrbing, with chunk_size < max_workers) does not degrade performance.

 chunk is the actual dictionary list of IPs to be processed per process

 chunks is the dictionary list of all of the IPs to be processed (the total len(instance_ips) of IPs)
 chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
 chunks is required to track the entire list of all the IPs because the desired_count cannot process them all
 in parallel initially and has to take up the extras serially as the pool of processes free up, one by one.

 args_list is the List of args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]  passed to the tomcat_worker function above
 using the pool.starmap pool.starmap(tomcat_worker, args_list) to assign the chunk blocks to each successive
 process running in parallel (initially the desired_count of processes)

 the configurable options are chunk_size, max_workers (like with model2) and desired_count
 The total number of EC2 instances are specified in the .gitlab-ci.yml and passed and env variables to the first
 python module in the python package for this project (11 modules so far)




## UPDATES:  BENCHMARKING part4: Hyperscaling the multi-processing


T3.small 200 instances with 200 processes and 1 thread per process (chunk_size =1)
At 200 the VPS got a bit stuck at around 137 but then proceeded to slowly create the rest of the processes.
So there is a bit o bottleneck hit here. We did not see this with 149 process test.  
I did see the VPS controller CPU go to 0 idle periodically so it was maxed out for short periods.

Once the processes were up and running thing proceeded as expected.
I did a quick spot check on AWS and all 200 instances have status up and checks are ok. And the python script did well screening for this.
Amazingly the entire script completed in about 7 minutes, just a bit longer than usual. This slight deviation is due to the process bring up being a bit slow once getting above 150 processes. 



T2.small 400 instances with 400 processes and 1 thread per process (chunk_size=1)

Change to t2.small. This might affect the control of the testing as these are slower to come up and the installation could be slower with 1 vCPU, but the focus is on the 400 processes and the mutli-processing with no multi-threading in each process (1 thread per process).
Have to switch to t2.small because AWS limit currently at 402 vCPUs and t3.small have 2 vCPU per instance.

This test hit a bottleneck with the VPS. CPU gets tapped out. The gitlab container is running a docker container that is runing the python master script.  The top shows the contention and the idle CPU drops to 0


```
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R 100.0   0.0  25:23.80 kswapd0                                            
1998254 root      20   0 1139656  10832   2128 S  41.5   0.1   3:50.24 fail2ban-server                                    
2005387 1001      20   0 1238948   9132   1196 S  28.9   0.1   0:47.86 go-camo    




    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R  72.1   0.0  25:32.10 kswapd0                                            
    456 root      20   0 2241208  13612   1652 S  23.4   0.1  28:28.77 containerd                                         
2616745 112       20   0  122344  79376   1396 D  21.4   0.5   0:01.59 amavisd-new                                        
   1302 root      20   0 3693788  34924   1900 S  18.8   0.2 210:26.35 dockerd   
```

Once this occurs the gitlab container also running on the VPS locks up.   Putting the gitlab container on a separate VPS would be a solution part of this problem.

### multi-processing issues:

With the testing above it revealed another issue. With processes greater than 25 there appears to be an issue with all of the EC2 instances getting tomcat9 actually installed. This is most likely caused by one or several of the issues below and we need to refine the python script using a variety of techniques to accomodate such edge cases.

Some of the causes might be due to:
VPS (6 vCPUs) + Docker + GitLab runner setup likely hits a resource ceiling when too many processes are spawned simultaneously. This causes:

- Process crashes or hangs
- Silent failures
- Incomplete logging


Stated more concisely:

  - Process management overhead
  - Docker or GitLab runner limits
  - Lack of proper inter-process error handling or logging

The silent failures and process crashes would not necessarily be caught by the curent code failure detection.


### Possible solutions that will be explored: 

To resolve this will have to try some of the folowing or all of the following approaches:
(these all effectively try to control the process concurrency since the problem cannot be resolved directly without 
changing the hardware, docker container distribution, etc.


1. Dynamic Process Scaling
   → Adjusts the number of processes based on system load or available CPUs  
   Prevents overload while still maximizing throughput

2. Process Pooling
   → Reuses a fixed number of worker processes  
   Lets you queue up 100+ tasks but only run, say, 25 at a time

3. Centralized Logging & Error Handling
   → Ensures no failures go unnoticed  
   Helps you detect and retry failed tasks

4. Task Queue Model (e.g., `multiprocessing.Queue` or `concurrent.futures`)  
   → Submit all 100+ tasks, but only a safe number run concurrently  
   Scales to hundreds of tasks without overwhelming the system



### production level soultions in real world would avoid this situation by properly configuring threads per process and chunk_size, etc....


- Increase `chunk_size` to reduce the number of processes
- Stay within the known-safe range (e.g., ≤25 processes)
- Scale horizontally if needed (e.g., split the workload across multiple VPS containers or runners)








## UPDATES: BENCHMARKING part 3:

After the extensive benchmark testing we can see the benefits of multi-processing and multi-threading.
Due to the VPS archlinux and docker effective use of multi-processing, there is no detriment when using a variety of
different chunk_sizes and thread counts. The key is that the chunk_size must be kept equal to or below the max_workers, i.e. the nubmer of threads 
(under provisioning the ThreadPoolExecutor has no determental cost).  As long as that is done, the number of processes can be increased up to 
149 processes with 1 thread per process for the high scale case (149 EC2 instances) or it can be spread out amongst a much
smaller number of processes (13) (for example chunk_size of 12 for 13 processes) or something in the middle with 
chunk_size of 2, for example for 75 processes. All of these permutations yield approximately the same completion time.
At this state, the bottleneck is the I/O time of the SSH connections and the installation time on each instance.
One other bottleneck is the type of EC2 instance. Moving from t2.micro to t3.small improved the time to Status ready
so that the SSH connections could be initiated sooner in the process.   imagine t3.large would improve the time even further in this respect. The installation time would also improve as well the larger the EC2 type.


Without any type of parallelism, i.e. removing the ThreadPoolExecutor and setting the chunk_size to 149 for one process, will show the effects of no parallelism at all. 
In this case, the test was going so slow I had to abort it as it would take hours.
This is compared to the roughtly 6:30 minutes for the parallelized versions that are provisioned correctly.
After aborting test, by the logs it looked like about 1 instance per minute, so 149 instances would have taken about 2.5 hours.

The final test is keeping the chunk_size at 149 for one process but adding back the multi-threading and max_workers of
149 for 149 threads.  Comment back in the ThreadPoolExecutor.  This will illustrate the multi-threading performance alone.This was at 6:50 minutes, closely aligned to the other optimized performances.

Conclusions: 

Multithreading alone is just as effective as multiprocessing for this I/O-bound workload — as long as thread provisioning is correct.

The real performance gain comes from concurrency, not from the specific mechanism (threads vs. processes).

The system (6 vCPU core VPS + Docker + Linux scheduler) handles both models efficiently. 

Also of note this scales well. There is no significant difference between 100 instance case and the 149 instance case as long as the chunk_size and number of threads are provisioned correctly for optimal processing (keep the chunk_size less than or equal to the number of threads).




## UPDATES: BENCHMARKING part 2: Scaling issues to EC2 instances > 100

Had to modify the python describe_instance_status as the DescribeInstanceStatus method overloaded for > 100 instances.

Create a helper function and batch process the EC2 instances so that this method can consume them properly

Helper function:

```
def describe_instances_in_batches(ec2_client, instance_ids):
    all_statuses = []
    for i in range(0, len(instance_ids), 100):
        batch = instance_ids[i:i + 100]
        response = ec2_client.describe_instance_status(InstanceIds=batch, IncludeAllInstances=True)
        all_statuses.extend(response['InstanceStatuses'])
    return all_statuses
```


Next issue is the gitlab-runner logs hit max at 4MB. Since this is a self-hosted runner, edit the /etc/gitlab-runner/config.toml with the following addition. NOTE the placement must be at the line below. it will not work otherwise. Restart the gitlab-runner as well.


```
[[runners]]
  name = "vps.****************.com"
  url = "https://**************.com"
  id = 1
  token = "***************************"
  token_obtained_at = 2024-10-09T21:19:49Z
  token_expires_at = 0001-01-01T00:00:00Z
  executor = "shell"
  output_limit = 10240 <<<<<<<<<<<< THIS MUST BE PLACED HERE and not further down.
  [runners.custom_build_dir]
  [runners.cache]
    MaxUploadedArchiveSize = 0
    [runners.cache.s3]
    [runners.cache.gcs]
    [runners.cache.azure]
```

The benchmarking consistes of a 12 thread 12 chunk_size for 13 process test compared to
2 thread 2 chunk_size and 75 process test to assess the effect of number of processes in the python multi-process
master file.

There does not appear to be any drag on the completion time with the 75 processes. The VPS CPU is ok during this as well.
The processes are run in a docker container and I did not see the docker daemon remarkable stressed during the pipeline run.




## UPDATES: BENCHMARKING part1: Summary of benchmark findings for module 2 (mutli-processing and multi-threading)



The key variables are num_processes, chunk_size and max_workers (number of threads). Some general early findings are listed below:

I ran a lot of benchmark tests. The number of processes is always adjusted to accommodate the chunk_size so the number of processes does not come into play.  I even ran model 3 which adds dummy processes and they don't appear to slow things down in terms of strict process overhead.      The key is the chunk_size relative to the the max_workers (number of threads). If the chunk_size is greater than the  number of threads the performance gets much worse (about 6.5 mintues vs. 9.5 minutes)     If the number of threads is equal to the chunk_size the performance is better. It does not improve or get worse if chunk size is reduced less than the number of threads (in other words the idle threads don't have a determinantal effect on overall time).  

If i increase the chunk size way over the thread count the performance is very poor and gets worse the more the oversubscription to the ThreadPoolExecutor. So good design definitely means that the chunk_size should be less than or equal to the max_workers (number of threads).  The performance suffers in line with how oversubscribed the thread pool executor is. For example with chunk size 8 and threads 6 it is at 8 minutes (6:30 minutes is the time it takes when thread pool executor is not oversubscribed and it is provisioned correctly). I then tried chunk size of 24 and threads 6 and it took 14:45 minutes! So much worse.  I did chunk_size of 12 and threads 6 and as expected is was in the middle of these at 9:30 minutes.    I then ran chunk size of 6 and threads 6 and  it was at what i refer to as the "normalized" time of 6:25. About 6.5 minutes seems to be the optimal time in terms of chunk size and thread provisioning.   

There might be some further optimizations that we can do with the number of processes for my 6 core VPS system, but i haven't seen any obvious advantages of restricting the number of processes to the number of cores(6) but this needs more examination and testing.  At a high level as long as the chunk size relative to thread count is provisioned correctly, I don't see any large differences in the different number of processes across these correctly provisioned cases (i.e, they all finish up in about 6.5 minutes)                Also as expected running a 12 thread with 24 chunk size, the time is better than the 6 thread and 24 chunk size, for example, as expected. (Even though both of these are not provisioned optimally). So the more oversubscription of the ThreadPoolExecutor the worse the performance. This aligns with more context switching as the oversubscription gets worse, causing worsening performance, and dramatically so.    

Another note. I ran tests with low number of threads (4) just to see if degree of oversubscription made a difference and from what I can tell it does. Comparing the results to the 6 thread case for the same chunk sizes, the 4 thread times are worse.

These times below for oversubscription are extremely bad because thread is so low at 4. Comparisons to thread 6 case are listed below as well and as expected they are a better than the tread 4 case, but still very suboptimal.



Chunk size 12 and threads  4
9 processes
Moderately oversubscribed
I see the 4 ip block process finish quite early since threads 4 is sufficient to process these ips quickly. It is the oversubscribed processes that lag a long time.(the other 8 processes)
12:09
Vs. 9:39 with 6 threads so it gets worse in expected fashion


Chunk size 8 and threads 4
13 processes
Lightly oversubscribed
9:30
Vs. 8 minutes with 6 threads. So it gets worse in expected fashion


Chunk size 24 and threads 4
5 processes
substantially subscribed
20:18
Vs. 14:45 with 6 threads. So it gets worse in expected fashion


Chunk size 4 and threads 4
25 processes
Correctly provisioned
(Expect this to be around 6:30)
6:50 so this is line with the expectation.

About the multi-processing dynamics:
Note when comparing this to the 6 thread and 6 chunk size case, with 17 processes there is very little difference. Both are correctly provisioned for chunk_size relative to number of threads per process which controls this test to baseline.
The process overhead (increase from 17 processes to 25 processes) does not seem to adversely affect the performance as long as the processes are not massively over provisioned is my conclusion (need to verify a massive overprovision with perhaps 200 EC2 instances and chunk_size of 2 for 100 processes).  With 6 VCPU cores, we are not constrained to 6 process optimal state.   I have not determined an optimal number of processes yet.

Another note with the test like this with chunk size equal to threads, is that I can observe the multi-processing at work very well.
Very roughly speaking all of the processes wrap up processing in about the last minute of the test run.   So they all start completing roughly in the same time frame. The archlinux VPS OS is doing a pretty good job distributing the threads in the processes over the 6 vCPU cores from what I can see. Otherwise we would see a large disparity in the completion times of the processes for their respective ip blocks.






## UPDATES:

further testing with multi-threading and multi-processing for tomcat installation module 2.
There are now 3 different models to test with this.   Increase EC2 to t3.small as that was a bottleneck as well.
These models provide testing flexibility and decouple the chunk_size from mum_processes (Models 2 and 3)

The max_workers for the ThreadPoolExecutor is defined separately and in an earlier code block. This is the number of threads per process

num_processes value is specified separately

The 3 models are below



Model 1:

Model 1: Fixed Number of Processes num_processes.  Chunk size is dynamic based upon the num_processes and number of ips. In the default case 50 Ips and 8 num_processes will use a chunk_size of 6 and remainder 2 in last process.  This has the new wait_for_public_ips code (see Mddel 2 for more detail on this), so the delay is no longer fixed but dynamic.  main() calls install_tomcat_on_instances for all three models so the multi-threading is done by ThreadPoolExecutor for all three models.  main() calls wait_for_public_ips prior to install_tomcat_on_instances so that we can be sure that public ips are present on all Ips in the the test pool.

- Number of processes is fixed (`num_processes`).
- Each process gets a chunk of IPs.
- The last process handles any remainder.
- Controlled parallelism, predictable resource usage.

```
    chunk_size = len(instance_ips) // num_processes
    processes = []

    for i in range(num_processes):
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
        if i == num_processes - 1:  # Add remaining instances to the last chunk
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
```


Model 2: (REMAINDER METHOD: don't use this)


```
chunk_size = 12
processes = []

>> Calculate how many full chunks we actually need
num_chunks = len(instance_ips) // chunk_size
remainder = len(instance_ips) % chunk_size

for i in range(num_chunks):
    chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
    
    >> If this is the last used chunk, add the remaining IPs
    if i == num_chunks - 1 and remainder > 0:
        chunk += instance_ips[(i + 1) * chunk_size:]

    process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    processes.append(process)
    process.start()

for process in processes:
    process.join()
```


Model 2:  (CEILING DIVISION METHOD: this is cleaner but does involve adding one additional process to deal with the
extra overflow of ips from chunk_size)

Model 2 (Revised): Fixed Chunk Size, Dynamic Process Count

- You define `chunk_size`, and the number of processes is calculated.
- Uses ceiling division to avoid remainder logic.
- Good for: Load balancing when you care more about chunk size than number of processes.
Using ceiling division, an additional process will be added to process the remaining IPs, rather than adding them to the
last process (model1)
Note new code is in here wait_for_public_ips so that there are no orphan EC2 instances that are not included in the last process.  The code is no longer fixed delay wait time but dynamic based upon a loop to check the public_ips on the instances, with exponential backoff algorithm for efficiency.

```
chunk_size = 12
processes = []

# Debugging instance_ips
print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')

# Calculate how many chunks we need (ceiling division)
num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size

for i in range(num_chunks):
    start = i * chunk_size
    end = min(start + chunk_size, len(instance_ips))  # safely cap the end index
    chunk = instance_ips[start:end]

    process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    processes.append(process)
    process.start()

for process in processes:
    process.join()


```


Model 3: REMAINDER METHOD (don't use this)

```
chunk_size = 12
processes = []

>> Calculate how many full chunks we need
num_chunks = len(instance_ips) // chunk_size
remainder = len(instance_ips) % chunk_size


for i in range(num_processes):
    if i < num_chunks:
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        if i == num_chunks - 1 and remainder > 0:
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    else:
        # Dummy process that just logs it's unused
        process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
    
    processes.append(process)
    process.start()


```




Model 3: CEILING DIVISION METHOD

Model 3 (Revised): Fixed Number of Processes, May Be Underutilized

- Always spawns `num_processes`, even if some are unused.
- Useful for testing or simulating a fixed pool of workers.
- Good for: Benchmarking or stress testing process overhead.
This is the same as Model2 except that the num_processes is always spawned regardless if they are required to process the number if IPs. . This uses the new wait_for_public_ips function as well.



```
chunk_size = 12
processes = []

# Calculate how many chunks we need (ceiling division)
num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size

for i in range(num_processes):
    if i < num_chunks:
        start = i * chunk_size
        end = min(start + chunk_size, len(instance_ips))
        chunk = instance_ips[start:end]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    else:
        # Dummy process that just logs it's unused
        process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))

    processes.append(process)
    process.start()

for process in processes:
    process.join()

```

## UPDATES:

Did extensive testing of the multi-processing vs. multi-threading environment for the master python file and also introduced the module 2 optimizations for the install tomcat module (with multi-processing and limit the multi-threading in the ThredPoolExecutor to 6, the number of VCPU cores on the VPS.

For the first set of tests determined that the multi-processing for the master python execution of the 11 modules is  bit faster than the muti-threaded version.  

Next testing is with the module 2 testing. First try without multi-processing within the module 2 (no main() calling function of the original function).   The original function does not use multi-processing (6 processes) to distribute the ThreadPoolExecutor SSH threading connections over all cores. This took about 10 minutes
This just starts the 50 threads across all of the 6 VCPU cores in a random fashion and could cause context switching issues and contention.

The modules 1 and 2 took 10:13




Next do the 6 processes and 6 threads for each process in the ThreadPoolExecutor
Modules 1 and 2 took 11:50

Next do 8 processes and 12 threads for each process in the ThreadPoolExecutor
Modules 1 and 2 took 9:37








## UPDATES:

Major overhaul of the second module for installation of tomcat onto each of the 50 EC2 instances that are placed in the ALB target group. This was running ok with the ThreadPoolExecutor but inefficently as there were 50 threads randomly executed across the 6 cores causing contention and a lot of context switching. New approach is running in the master script that is running multi-processing. Then the changes were made to the second module that installs tomcat on each of the 50 EC2 instances.   This involved adding a main() function to the module that wraps around the original install module.   The main() functino institutes multi-processing.   First 6 processes are started because the VPS is 6 core CPU. . Each process then invokes the original tomcat function that was modified to only run 6 threads per function call instead of 50 threads like before. So each process in main() calls the install tomcat function which runs 6 threads to consume the block of ip addresses allocated to each process.

The chunk ip allocation block of ips is in the main() function below and is detailed below.  For example with 50 IP addresses and 6 processes there is an 8 block of ips assigned to each process. Because there is an extra 2 IPs there is math logic in the chunk code to assign the remaining IPs (in this case 2) to the last process an the last process will consume them.(10 ip addresses in this case).

Further detail in install_tomcat_on_instances original function:


```
### HERE IS THE MAIN CHANGE FOR THE multiprocessing optmization. First we are going to tie the thread pools
    to the number of cores (the VPS has 6 CPU cores).  Each ThreadPoolExecutor will have max workers of 6 at a time.
    Previously we had max_workers set to length of public_ips which is 50. This is creating a lot of contention with only
    6 cores and a lot of context switching.    To optimize this first we will restrict this to the os.cpu_count of 6
    This means that there will be 6 threads at the same time. To further optimize this with main() function below, we 
    will also start 6 processes defined by num_processes=os.cpu.count (6 as well.  Each process wil invoke the 
    install_tomcat_on_instances function running the 6 ThreadPoolExecutor threads on its dedicated core.   Thus there
    are on average 6 threads running on a process on each of the 6 cores, for 36 concurrent SSH tomcat installations
    at any time. This will reduce the contention of just running ThreadPoolExecutor with all 50 threads randomly assigned
    across the cores which created a lot of context switching. NOTE that chunk size is another variable. See main() below
    Chunk size is the chunk of ips that are grabbed by each process. So if 50 ip addresses each of the 6 processes will
    get 8 ip addresses, and each process can use the 6 threads in the process to process the SSH connections.  In this
    case 6 ips processed immediately and then the other 2 when some of the 6 threads are done with the initial 6 ips.
    however need additionl logic because with 50 instances and 6 processes there are 2 "orphaned" ips that need to be
    dealt with. This requires additional logic.

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]
```




Further detail in main():

```
### Use multi-processing to distribute SSH connections across multiple cores
    num_processes = os.cpu_count()
    
      the chunk_size is determined by number of instances divided by num_processes. num_processes is 6 and 
     number of instances is 50 so 50/6 = 8. The division is // for an integer with floor division
     this chunk size is then used to calculate the block of ips to pass to install_tomcat_on_instances (see below)
     for each process iteration i= 0 to num_processes-1 or 0 to 5 for processes 1 through 6
     Each process is assigned a block of 8 with the last 2 leftovers assigned to the last chunk which is assigned 
     to the last process #6. So the last process will get 10 ips to process. 
     As noted above the processes utlize install_tomcat_on_instances which runs ThreadPoolExecutor of 6 threads to
     process the assigned ip block.  So 6 ips handled immediately and the other 2 when any other thread frees up
     This minimizes contention and context switching.
    
    chunk_size = len(instance_ips) // num_processes
    processes = []

    for i in range(num_processes):
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
        if i == num_processes - 1:  # Add remaining instances to the last chunk
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
```




## UPDATES:

Running on 11 modules in multi-processing master script. This is running fine. This is using the function approach as well from the master script. Running on 6 processes because the VPS has 6 cores.


## UPDATES:

Now running all 11 modules in multi-threaded environment, with each of 11 modules running as a dedicated thread and grouping several of them for concurrency to speed up the infra rollout. The execu function call in the master python script ended up causing many scope related issues in the first 6 modules. I converted the entire script to a function call based multi-threading and wrapped all the python files in the package directory in dedicated function that is called from the master. The master python script is below for reference.   This runs very well all the way through without any scope related issues.

commit:
    major overhaul of multithreaded set up for all 11 modules. The first 6 modules had several scope related issues and so converted the master python script use function calls to the modules rather than exec function which has scoping issues. Had to wrap all modules in their respective function call names. Referring to them by path name rather than module object name but either approach is fine


The thread that takes the longest, the installation of tomcat on each of the 50 EC2 instances cannot be parallelized with any of the other treads because the EC2 instances are in the target group and tomcat has to be running so that the ALB passes target health checks when the ALB is created.

```
def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    with open(module_script_path) as f:
        code = f.read()
    exec(code, globals())
    logging.critical(f"Completed module script: {module_script_path}")

def restart_ec_multiple_instances():
    run_module("/aws_EC2/sequential_master_modules/restart_the_EC_multiple_instances_with_client_method_DEBUG.py")

def install_tomcat_on_instances():
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py")

def save_instance_ids_and_security_group_ids():
    run_module("/aws_EC2/sequential_master_modules/save_instance_ids_and_security_group_ids_to_json_file.py")

def create_application_load_balancer():
    run_module("/aws_EC2/sequential_master_modules/create_application_load_balancer_for_EC2_tomcat9_instances_json_pretty_format_BY_ALB_NAME.py")

def ssl_listener_with_route53():
    run_module("/aws_EC2/sequential_master_modules/SSL_listener_with_Route53_for_ACM_validation_with_CNAME_automated_3_BY_ALB_NAME.py")

def wget_debug():
    run_module("/aws_EC2/sequential_master_modules/wget_debug4.py")

def elastic_beanstalk():
    run_module("/aws_EC2/sequential_master_modules/Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS.py")

def rds_and_security_group():
    run_module("/aws_EC2/sequential_master_modules/RDS_and_security_group_json.py")

def jumphost_for_rds_mysql_client():
    run_module("/aws_EC2/sequential_master_modules/jumphost_for_RDS_mysql_client_NEW3.py")

def wget_for_elastic_beanstalk_alb():
    run_module("/aws_EC2/sequential_master_modules/wget_for_elastic_beanstalk_ALB.py")

def https_wget_for_elastic_beanstalk_alb():
    run_module("/aws_EC2/sequential_master_modules/HTTPS_wget_for_elastic_beanstalk_ALB.py")

def main():
    thread1 = threading.Thread(target=restart_ec_multiple_instances)
    thread1.start()
    thread1.join()

    thread2 = threading.Thread(target=install_tomcat_on_instances)
    thread2.start()
    thread2.join()

    thread3 = threading.Thread(target=save_instance_ids_and_security_group_ids)
    thread3.start()
    thread3.join()

    thread4 = threading.Thread(target=create_application_load_balancer)
    thread4.start()
    thread4.join()

    thread5 = threading.Thread(target=ssl_listener_with_route53)
    thread5.start()
    thread5.join()

    thread6 = threading.Thread(target=wget_debug)
    thread7 = threading.Thread(target=elastic_beanstalk)
    thread8 = threading.Thread(target=rds_and_security_group)
    
    thread6.start()
    thread7.start()
    thread8.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread6.join()
    thread7.join()
    thread8.join()

    thread9 = threading.Thread(target=jumphost_for_rds_mysql_client)
    thread10 = threading.Thread(target=wget_for_elastic_beanstalk_alb)
    thread11 = threading.Thread(target=https_wget_for_elastic_beanstalk_alb)

    thread9.start()
    thread10.start()
    thread11.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread9.join()
    thread10.join()
    thread11.join()

if __name__ == "__main__":
    main()
```


## UPDATES:

Added back in all the other modules for the modularized project.  There are a total of 11 modules at this time. The challenges were that there was no delay between first module (initialization of the EC2 instances) and the rest of the modules. The tomcat installation module requires that all instances be in Passed state in order to use the paramiko library to ssh into the EC2 instances and install tomcat. The public ip addreses need to be fully initialized on each instance to do this.  Adding a delay in the tomcat script got it working.

Moving the export of the instance ids and security group ids module to AFTER the tomcat installation module resolved another issue.  The export arrays were empty when this was executed as second module because the EC2 instances were not in fully running state. Once this was moved to the third module (non-multi-threaded), the fourth module which needs the instance id and security group id arrays started working.  This is because the second module (that is now the tomcat installation module) ensures that all EC2 instances are runnning and status checks are passed.  The fourth module, the manual ALB setup works fine now. After these changes the rest of the 11 modules ran fine including the beanstalk and RDS setups and the RDS jumphost as well as the wget stress EC2 generators for both the manual ALB and the beanstalk ALB instances (HTTP and HTTPS listeners).


## UPDATES:

Added large code changes for modulatization of the project, using packcage sequential_master_modules for the standalone python scripts.  master_script.py has non-parallelized version, and multi-threaded version and a multiprocessing version to optimize the deployment to AWS3. Broke off the RDS configuration from the beanstalk environment configuration as well so that can parallelize more effectively. RDS jumphost configuration added as well and it configures the RDS server with the basics for mydatabase.

There were several challenges encountered in making the threads 3 and 4 and 5 multi-threaded, in particular with threads 4 and 5 for http and https wget stress clients.  The error checking to checking instance status Ready and status and system checks ok was problematic.  Several changes had to  be made in this area.

Also making the code multi-threaded caused a lot of scope issues with the functions in the modules that are multi-threaded. The import of the libraries had to be done in the functions themselves to alleviate the scope issues.


## UPDATES:

See below as well.
Latest changes for AWS3 account are added elastic beanstalk environment and application and added wget stress traffic to that beanstalk URL (CNAME)

IAM class is required because instance_profile required to be attached to the beanstalk environment.  The instance_profile is a legacy object that holds the beanstalk role that has the folowing policies in it:
policies = [
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier',
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier'



```
### boto3 classes:

elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')
eb_client = session.client('elasticbeanstalk')
iam_client = session.client('iam')
```



Also added HTTPS 443 listener to the elastic beanstalk ALB loadbalancer.  This requires a lot of code for the certificate. To get the SSL cert issues have to create a hosted domain in Route53 and add the A record of the DNS URL (CNAME) of the elastic beanstalk ALB loadbalancer, then once the CNAME is ready for the cert request add the CNAME to the Route53 hosted zone as a CNAME Record for DNS Validation of the cert so that it transitions into issued state. Once have the cert had to manually get the load_balancer_arn and target_group_arn of the existing ALB in the beanstalk environment and also use this newly issued certificate_arn to create the HTTPS 443 listener manually using the elbv2 boto3 class/method. The elasticbeanstalk method did not work for me.   
Finally add HTTPS traffic to the wget traffic generator EC2 instance so that HTTP and HTTPS are simultaneously sent to the the beanstalk ALB.

## ORIGINAL

This python project creates an ALB on AWS using a target group of 50 EC2 instances running an installed tomcat.  THe listener 
frontend is both https/ssl and http.   There is also a stress traffic EC2 generator that is also created to generate
stress traffic to the https listener.   The traffic can be monitored on the access logs of the ALB which are also 
configured using python. The following python classes are used to create this infrastructure using the boto3 SDK.


This uses a wrapper script to execute the modules as separate python script files.   

The SSL/TLS uses the acm class to create the cert. The CNAME has to be tested and so Route53 has to be employed to do this, using an A record to alias the ALB URL to the Route53 hosted zone. It works very well.

The following boto3 client classes are used so far:


```
class EC2.Client
class ElasticLoadBalancingv2.Client
class acm.Client

session.client('ec2')
elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')
```



Note: the autoscaling is not used for now as I need to create an effective destroy script as well for that. 



The wget EC2 instance stress generator:

```
Last login: Tue Apr  8 00:38:28 2025 from 172.31.21.52
ubuntu@ip-172-31-86-66:~$ ls
stress_test.sh
ubuntu@ip-172-31-86-66:~$ ps -ef |grep stress_test.sh
ubuntu      6336    6234  7 00:43 pts/1    00:00:00 grep --color=auto stress_test.sh
ubuntu@ip-172-31-86-66:~$ ls
stress_test.sh
ubuntu@ip-172-31-86-66:~$ tcpdump -i eth0 dst port 443
tcpdump: eth0: You don't have permission to capture on that device
(socket: Operation not permitted)
ubuntu@ip-172-31-86-66:~$ sudo tcpdump -i eth0 dst port 443
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:44:22.452595 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [.], ack 2974631937, win 459, options [nop,nop,TS val 2682466045 ecr 4009966254], length 0
00:44:22.456935 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [P.], seq 0:126, ack 1, win 459, options [nop,nop,TS val 2682466049 ecr 4009966254], length 126
00:44:22.458001 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [P.], seq 126:309, ack 205, win 458, options [nop,nop,TS val 2682466050 ecr 4009966330], length 183
00:44:22.462674 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [.], ack 2352, win 442, options [nop,nop,TS val 2682466055 ecr 4009966334], length 0
00:44:22.534144 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [F.], seq 309, ack 2352, win 442, options [nop,nop,TS val 2682466126 ecr 4009966334], length 0
00:44:22.534762 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [R], seq 3372935856, win 0, length 0
00:44:22.534804 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [R], seq 3372935856, win 0, length 0
00:44:22.541068 IP ip-172-31-86-66.ec2.internal.43884 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [S], seq 3906347289, win 62727, options [mss 8961,sackOK,TS val 2
```

ALB Access logs show the loadbalancing to the backend:


The client and socket and the target EC2 instance (there are 50 of them) and the socket (8080)


```
https 2025-04-08T00:42:18.719308Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45808 172.31.87.99:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ea-440e2a275a742e0034a8b8c7" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:18.715000Z "forward" "-" "-" "172.31.87.99:8080" "200" "-" "-" TID_c058d0218cb28142a303b654f4f7c035
https 2025-04-08T00:42:18.906898Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45852 172.31.93.134:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ea-69b79ad0408104c00b50d2ef" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:18.903000Z "forward" "-" "-" "172.31.93.134:8080" "200" "-" "-" TID_d26d051d522b804498afa60e8922f3f5
https 2025-04-08T00:42:19.054746Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45890 172.31.84.229:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-054849b625c3282066db139e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.052000Z "forward" "-" "-" "172.31.84.229:8080" "200" "-" "-" TID_3ba0637db38e844ebde8a74f9887f966
https 2025-04-08T00:42:19.090741Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45892 172.31.84.204:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-1dc1077403b2551c412ef503" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.088000Z "forward" "-" "-" "172.31.84.204:8080" "200" "-" "-" TID_a24f144f195f5f498efaf0315dbf40d4
https 2025-04-08T00:42:19.108930Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45900 172.31.83.238:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-6238efbf5d8b11137ee036d4" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.104000Z "forward" "-" "-" "172.31.83.238:8080" "200" "-" "-" TID_1734351bfe9693479e8f4a23cb2d3bbc
https 2025-04-08T00:42:19.144177Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45912 172.31.89.170:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-2b943f924aa0d4627273f3ba" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.141000Z "forward" "-" "-" "172.31.89.170:8080" "200" "-" "-" TID_2442f548a6429c40acf4a06e73fbb920
https 2025-04-08T00:42:19.181414Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45920 172.31.83.192:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-6f4ae2d26fa9a3194b558600" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.176000Z "forward" "-" "-" "172.31.83.192:8080" "200" "-" "-" TID_536249c7882634459b30112fa081086a
https 2025-04-08T00:42:19.289057Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45952 172.31.81.228:8080 0.002 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-197042313f8d077c34fabf32" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.284000Z "forward" "-" "-" "172.31.81.228:8080" "200" "-" "-" TID_f437e2f588025e489488c3d26be213f8
https 2025-04-08T00:42:19.377019Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45968 172.31.82.19:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-549336667d9a20f309dc7f01" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.373000Z "forward" "-" "-" "172.31.82.19:8080" "200" "-" "-" TID_a3b426c20cf58e418b7d714b7ab0492e
https 2025-04-08T00:42:19.409220Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45990 172.31.87.16:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-5a4da9a945238de25a84284e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.407000Z "forward" "-" "-" "172.31.87.16:8080" "200" "-" "-" TID_6b3362a719b6c148a01ce8c0d0235b29
https 2025-04-08T00:42:19.444768Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45998 172.31.85.85:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-0c289d8271aeb9603917d732" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.442000Z "forward" "-" "-" "172.31.85.85:8080" "200" "-" "-" TID_6758638dc9f4be4d93091ac359beef6b
https 2025-04-08T00:42:19.463656Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46008 172.31.86.16:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-4984f3394a758b1968b9da58" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.458000Z "forward" "-" "-" "172.31.86.16:8080" "200" "-" "-" TID_9f4a2d3c5cee874ea5b3e71dc0a292ea
https 2025-04-08T00:42:19.510454Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46032 172.31.93.38:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-3370f07b51979a5e080d40b1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.506000Z "forward" "-" "-" "172.31.93.38:8080" "200" "-" "-" TID_6329eb37a865a749aa27d0b9a4fea65e
https 2025-04-08T00:42:19.577794Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46034 172.31.94.59:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-0e383ffa217f8529600d4fdd" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.574000Z "forward" "-" "-" "172.31.94.59:8080" "200" "-" "-" TID_6e5df171195dcf4887dc79e34de4ebd0
https 2025-04-08T00:42:19.700430Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46052 172.31.89.105:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-2bf3c307349ce2e46172e95f" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.696000Z "forward" "-" "-" "172.31.89.105:8080" "200" "-" "-" TID_c1378c55075d2446850f3dab0b442f94
https 2025-04-08T00:42:19.864127Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46074 172.31.95.109:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-16fc7e72604f5fae04048cdd" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.860000Z "forward" "-" "-" "172.31.95.109:8080" "200" "-" "-" TID_5aa286b3f793e54ea2a312d01900eae6
https 2025-04-08T00:42:19.938048Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46088 172.31.90.94:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-323f680a74ea64e53975dcda" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.934000Z "forward" "-" "-" "172.31.90.94:8080" "200" "-" "-" TID_5b7085dddad858419ce7c68f82fe743c
https 2025-04-08T00:42:19.987400Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46094 172.31.81.138:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-261e946d423b8854525d164e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.985000Z "forward" "-" "-" "172.31.81.138:8080" "200" "-" "-" TID_7698b513a8a13341aa145df3f68036dc
https 2025-04-08T00:42:20.023750Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46116 172.31.84.185:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-4b4a5a66581cef4319ebd5f6" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.020000Z "forward" "-" "-" "172.31.84.185:8080" "200" "-" "-" TID_a55fab4bce194c4b83e0ff88d3f1d63b
https 2025-04-08T00:42:20.059098Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46126 172.31.92.63:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-76eadfc60d6b8b42602ed0b1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.054000Z "forward" "-" "-" "172.31.92.63:8080" "200" "-" "-" TID_cee51ee452a7b74780e6e8880c51f406
https 2025-04-08T00:42:20.120100Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46142 172.31.94.160:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-683ecd4b140e253a0827bee6" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.116000Z "forward" "-" "-" "172.31.94.160:8080" "200" "-" "-" TID_aa953d4641c4434cb032f2aecf315933
https 2025-04-08T00:42:20.219465Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46146 172.31.83.105:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-088c40af730a61d80044f8d2" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.217000Z "forward" "-" "-" "172.31.83.105:8080" "200" "-" "-" TID_97e7b25a5aa8604f9e843fb20c255eee
https 2025-04-08T00:42:20.445742Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46204 172.31.88.90:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-762531377c53150428c829d1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.443000Z "forward" "-" "-" "172.31.88.90:8080" "200" "-" "-" TID_0c5934f18f4d81489860565f1b94e0a1

```



