# This is the mutli-processing version of the multi-threaded version
# All 11 modules are included
#### This is the spawn version of the master script file. Each process worker will be spawned rather than forked.
#### The master_script.py will use default fork. This file uses spawn.


import logging

#### These are for the refactored def run_test below for spawned rather than forked processes in the modules (module2 is the only
#### one that requires this but we have to do it for all the modules in the package. This is good practice too.
import importlib.util
import sys
import logging
import os ## this is for the module2e special case in def run_module



import multiprocessing

# Make sure the sequential_master_modules directory is importable in parent and workers
sys.path.append("/aws_EC2/sequential_master_modules")

## enable spawn mode multi-processing. Force spawn mode for all multiprocessing in this pipeline
multiprocessing.set_start_method("spawn", force=True)

print("[SPAWN_MODE] multiprocessing start method:", multiprocessing.get_start_method())





logging.basicConfig(level=logging.CRITICAL, format='%(processName)s: %(message)s')

#### This is the spawn version of the mster script multiprocessing. Use teh def run_module below this original one.

#### Original used with forking:
#def run_module(module_script_path):
#    logging.critical(f"Starting module script: {module_script_path}")
#    with open(module_script_path) as f:
#        code = f.read()
#    exec(code, globals())
#    logging.critical(f"Completed module script: {module_script_path}")






#### This is the spawn version of the def run_test function above. 
#### 
#- **Do not** use `globals()` for exec.
#- Use a **fresh dict** and explicitly set `__name__ = "__main__"`.
#- This makes the module’s own (each module's):
#
#  ```
#  if __name__ == "__main__":
#      main()
#  ```
#
#  behave exactly as if it were run as a script.
# No changes need to be made in the above inside each module in this package!

#def run_module(module_script_path):
#    logging.critical(f"Starting module script: {module_script_path}")
#    with open(module_script_path) as f:
#        code = f.read()
#
#    # Create a fresh namespace where __name__ is "__main__"
#    module_ns = {"__name__": "__main__"}
#
#    exec(code, module_ns)   ## use module_ns instead of globals which will use the python module's filename. We don't want that.
#
#    logging.critical(f"Completed module script: {module_script_path}")





#### Need to refactor again for the spawn version
# ------------------------------------------------------------------------------
# WHY THIS CUSTOM MODULE LOADER EXISTS (SPAWN-SAFE EXECUTION)
#
# Python’s multiprocessing “spawn” start method launches a completely fresh
# interpreter for every worker process. Unlike “fork”, the child does NOT inherit
# the parent’s memory, globals(), or dynamically exec’d code.
#
# That means:
#   - Any function used by a multiprocessing Pool worker MUST be importable
#     by module name (e.g., module2_install_tomcat_patch8_99.tomcat_worker_wrapper)
#   - Code executed via exec(..., globals()) is NOT importable, because it has
#     no module identity and lives only in the parent’s memory.
#
# If a worker cannot import the function, spawn raises:
#       PicklingError: Can't pickle <function ...>: attribute lookup failed
#
# To fix this, we load each module using importlib with a real module name:
#
#   1. Create a module spec from the file path
#   2. Create a module object
#   3. Register it in sys.modules under its filename (minus .py)
#   4. Execute the module inside that module object
#
# This gives the module a proper identity, so spawn workers can import it.
#
# IMPORTANT:
#   - No changes are required inside module2 or any other module.
#   - Functions like tomcat_worker_wrapper become importable automatically.
#   - This loader is only needed because the master script dynamically loads
#     modules instead of importing them normally.
#
# This keeps the architecture intact while making it fully spawn-compatible.
# ------------------------------------------------------------------------------

def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")

    module_name = module_script_path.split("/")[-1].replace(".py", "")

    spec = importlib.util.spec_from_file_location(module_name, module_script_path)
    module = importlib.util.module_from_spec(spec)

    # Register module so spawn workers can import it
    sys.modules[module_name] = module

    # Execute module code. This will attempt to use the module file name to load the module. So need to add the next line below if hasattr
    # and load each module from this master script instead.
    spec.loader.exec_module(module)

    # Special case for module1
    if module_name == "restart_the_EC_multiple_instances_with_client_method_DEBUG":
        if hasattr(module, "restart_ec_multiple_instances"):
            module.restart_ec_multiple_instances()
        
        logging.critical(f"Completed module script: {module_script_path}")
        return


    # Special case for module2d (resurrection gatekeeper)
    if module_name == "module2d_resurrection_gatekeeper":
        # Run module2d.1
        if hasattr(module, "main") and callable(module.main):
            module.main()

        # Run module2d.2a and 2d.2b
        if hasattr(module, "process_ghost_registry") and callable(module.process_ghost_registry):
            module.process_ghost_registry()

        # Run module2d.3
        if hasattr(module, "merge_resurrection_registries") and callable(module.merge_resurrection_registries):
            module.merge_resurrection_registries()

        # Run module2d.4
        if hasattr(module, "aggregate_gatekeeper_stats") and callable(module.aggregate_gatekeeper_stats):
            module.aggregate_gatekeeper_stats()
    
        logging.critical(f"Completed module script: {module_script_path}")
        return


    # Special case for module2e (Phase3 requeue + reboot)
    if module_name == "module2e_reque_and_resurrect_Phase3_version2":
        # Run module2e main()
        if hasattr(module, "main") and callable(module.main):
            module.main()

        # Run the post-processing reboot function
        if hasattr(module, "batch_reboot_registry") and callable(module.batch_reboot_registry):
            module.batch_reboot_registry(region=os.getenv("region_name"))   ## make sure to import os at the top!!

        logging.critical(f"Completed module script: {module_script_path}")
        return



    # Normal case for all other modules that have a main(). If the module defines a main() functin, call it here with spawned modules.
    if hasattr(module, "main") and callable(module.main):
        module.main()

    logging.critical(f"Completed module script: {module_script_path}")








## module 1:

def restart_ec_multiple_instances():
    run_module("/aws_EC2/sequential_master_modules/restart_the_EC_multiple_instances_with_client_method_DEBUG.py")



## module 2 variants for testing:

# this one will run with the mutli-processing chnanges to the module2 with 6 processes and 6 threads per process. Chunk size is at 8 here.
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py")

# this one will run without the multi-processing changes to the module2
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_ORIGINAL_without_main.py")

# DEFAULT:: this one will run wiht multi-processing chnages to the module2 with 8 processes and 12 threads per process. Note that chunk size is down to 6
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12.py")

# TEST: This one will run the NEW ALGORITHM, effectively 5 processes and 12 threads with chunk size of 12
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_NEW_ALGORITHM_with_multiprocessing_main.py")




####### USE THIS AS STANDARD MODULE2 SCRIPT prior to REFACTOR
#######  Models 1-3 are avaliable with model 2 preferred for testing.

# this is also called install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_BACKUP_PRIOR_TO_REFACTOR.py
#  IMPROVED public ips for instance_ips version. This is often a problem. If AWS is bogged down this code is more 
#  resilient to handle fluctuations in service time getting the EC2 instances with public_ips
#  The delay is no longer fixed and deterministic but is dynamic based on a loop testing for the public ips, private ips
#  and instance id. The new function is wait_for_all_instances
## This is the main working module2 for the extensive benchmark testing and optimization on this module.

#Def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips.py")
#



######## THIS IS THE REFACTORED MODULE2 SCRIPT FOR POOLING WITH THE MULTIPROCESSING TO HANDLE HYPER-SCALING
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_REFACTORED_multiprocessing_pooling.py")
#



####### THIS IS THE MODULE2 SCRIPT WITH BENCHMARK LOGGING PER PROCESS (multi-threading benchmarking) without the wrapper fix
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_REFACTORED_multiprocessing_pooling_LOGGING.py")
#
#


####### THIS IS THE MODULE2 SCRIPT with logging per process and with the fix for pooled/queued process loogging
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_REFACTORED_multiprocessing_pooling_LOGGING_wrapper.py")
#



###### THIS IS THE MODULE2 SCRIPT with logging per process, pooled process fix and fix for empty log files
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_REFACTORED_multiprocessing_pooling_LOGGING_wrapper_buf.py")
#



###### THIS IS THE MODULE2 SCRIPT for logging in main() for higher level logging on the process and pool process orchestration
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12_wait_for_all_public_ips_REFACTORED_multiprocessing_pooling_LOGGING_wrapper_buf_MAIN_LOGGING.py")
#




###### THIS IS THE MODULE2 SCRIPT latest work for the SSH refactoring in install_tomcat
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR.py")
#



###### THIS IS THE MODULE2 SCRIPT latest work for the SSH refactor4 (phase2) in install_tomcat
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_res.py")
#

###### THIS IS THE MODULE2 SCRIPT latest work for the SSH refactor4 (phase2b with modified resurrection code detection) in install_tomcat
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_res2.py")
#

###### THIS IS THE MODULE2 SCRIPT latest work for the SSH refactor4 (phase2d with modified resurrection code detection patches 5,6) 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_res3.py")
#

###### THIS IS THE MODULE2 SCRIPT latest work for the SSH refactor4 (phase2d with modified resurrection code detection patch 7))
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_res3_patch7.py")

#### THIS IS THE MODULE2 SCRIPT with debugging for the artifact logging in the patch7b code
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_res4.py")

##### THIS IS THE MODULE2 SCRIPT with debugging for the artifact logging in the patch7c code
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_z_REFACTORED_LOGGING_MAIN_LOGGING_SSH_REFACTOR_zpatch7c.py")

#### THIS IS THE MODULE2 SCRIPT with patch7c and the aggregator in run_test (inline). This does not work as the processes do NOT
#### share memory
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_aggregator.py")


##### THIS IS THE MODULE2 SCRIPT with patc7c and post execution process level aggregator in tomcat_worker and main()
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_USE.py")


##### THIS IS THE MODULE2 SCRIPT with patch7c and post execution process level aggregator using write to disk (docker container disk)
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk.py")







##### THIS IS THE MODULE2 SCRIPT with adaptive watchdog timeout code added to write to disk
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog.py")




##### THIS IS THE MODULE2 SCRIPT with adaptive watchdog timeout code added to write to disk with debugs for control plane issue
##with PublicIps assignment/AWS issue
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug.py")


##### THIS IS THE MODULE2 SCRIPT with adaptive watchdog timeout code added to write to disk and patch7d res monitor code
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d.py")
#

##### THIS IS THE MODULE2 SCRIPT with res monitor patch7d changes to tomcat_worker and threaded_install for instance_info
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_1.py")


##### THIS IS THE MODULE2 SCRIPT with res monitor patch7d2 breaking up into subfunctions and restructuring
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_2.py")


##### THIS IS THE MODULE2 SCRIPT with res monitor patch7d3 going back to migrate from benchmark_ips to chunks for gold ip list to be used for ghost detection
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_3.py")

##### THIS IS THE MODULE2 SCRIPT with res monitor patch7d3 going back to migrate from benchmark_ips to chunks for gold ip list to be used for ghost detection
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_4.py")


##### THIS IS THE MODULE2 SCRIPT with stub logic in the threaded_install
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_5.py")
#


##### THIS IS THE MODULE2 SCRIPT with stub logic in the threaded_install
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch7d_6.py")


##### THIS IS THE MODULE2 SCRIPT with resurrection code changes moving out of install_tomcat and added to resurrection_monitor_patch8
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8.py")


##### THIS IS THE MODULE2 SCRIPT with resurrection code changes starting with the refactor of read_output_with_watchdog
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_2.py")

##### THIS IS THE MODULE2 SCRIPT with new gating logic for stubs and failures from output of read_output_with_watchdog into install_tomcat
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_3.py")



###### THIS IS THE MODULE2 SCRIPT with refactoring of read_output_with_watchdog to raw instead of stream output
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4.py")


##### THIS IS THE MODULE2 SCRIPT with refactoring of install_tomcat with whitelist logic
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4b.py")


##### THIS IS THE MODULE2 SCRIPT with testing on 512 node and APT Whitelist additions
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4c.py")


#### THIS IS THE MODULE2 SCRIPT strace testing and strace whitelist additions 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4c1.py")


##### THIS IS THE MODULE2 SCRIPT with wrapper code for command agnotic approach to support bash and bash-like commands, etc.
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4d.py")


##### THIS IS THE MODULE2 SCRIPT with the refactor for the adaptive watchdog timeout and fix API congestion.
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_5.py")


##### THIS IS THE MODULE2 SCRIPT with the refactor for the adaptive watchdog timeout refactoring continued.
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_5b.py")


##### THIS IS THE MODULE2 SCRIPT with code to determine why SG blocks are not executing in tomcat_worker
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_5c.py")


###### THIS IS THE MODULE2 SCRIPT with code to for refactoring resurrection_monitor_patch8 RESMON_8
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_6.py")



###### THIS IS THE MODULE2 SCRIPT with code to for refactoring resurrection_monitor_patch8 RESMON_8 and getting rid of res reg lock
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_6b.py")


###### THIS IS THE MODULE2 SCRIPT with code to for refactoring resurrection_monitor_patch8 RESMON_8 and fixing 512 install_failed misclassification
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_6c.py")


###### THIS IS THE MODULE2 SCRIPT with code to for refactoring resurrection_monitor_patch8 RESMON_8 and adding the new ghost detection logic
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_6d.py")


###### THIS IS THE MODULE2 SCRIPT rename of the patch8_6d.py (it is the same file). This has synthetic ghost injection code 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_6d.py")


###### THIS IS THE MODULE2 SCRIPT  patch8_7.py. This has the modularization using detect_ghosts function
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_7.py")


###### THIS IS THE MODULE2 SCRIPT  patch8_8.py. This has the process level ghost ip injection and the process level stats using res monitor function 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_8.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_9.py. This has the process level stats implementation using res monitor function 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_9.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_91.py. This has the code changes for AWS stop and start to recover status1/2 in Phase3 code
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_91.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_92.py. This has the BATCH code changes for AWS stop and start to recover status1/2 in Phase3 code
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_92.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_93.py. This has the code for Phase3 command json file that will be used in module2e for resurrection
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_93.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_94.py. This has the code for refactoring the SG rule application and Phase3 SG rule mainifest file (json) creation for module2e replay of SG rules. 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_94.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_95.py. This has the code for refactoring#2 of  the SG rule application and Phase3 SG rule mainifest file (json) creation for module2e replay of SG rules. This new code calculates delta from SG_RULES of pipelines. 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_95.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_96.py. This has the code for refactoring#3 of  the SG rule application and Phase3 SG rule mainifest file (json) creation for module2e replay of SG rules. This new code calculates delta using S3 for stateful SG_RULES across pipeline runs
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_96.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_97.py. This has the code for refactoring of the SG rule application loop in tomcat_worker for the stateful SG rule application design steps 1-4
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_97.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_98.py. This has the code for debugging the 16 node futures crash with the SG rule revoke of step4 of the SG_STATE design implemenation. 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_98.py")

###### THIS IS THE MODULE2 SCRIPT  patch8_99.py. This has the code for debugging#2 the 16 node futures crash with the SG rule revoke of step4 of the SG_STATE design implemenation. 
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_99.py")

##### THIS IS THE MODULE2 SCRIPT  patch8_991.py. This has the code for ssh instrumentation code for the SSH SYN issue with SG rule revoke
def install_tomcat_on_instances():
    run_module("/aws_EC2/sequential_master_modules/module2_install_tomcat_patch8_991.py")







##### This is module2b for the post ghost analysis on the gitlab console logs
def post_ghost_analysis():
    run_module("/aws_EC2/sequential_master_modules/module2b_post_ghost_analysis.py")

##### This is module2c for the post aggregate registry analysis on the gitlab console logs
def post_aggregate_registry_analysis():
    run_module("/aws_EC2/sequential_master_modules/module2c_post_registry_analysis.py")


#### This is module2d for the resurrection gatekeeper and supporing code
def resurrection_gatekeeper():
    run_module("/aws_EC2/sequential_master_modules/module2d_resurrection_gatekeeper.py")

##### This is module2e for the Phase3 reque and resurrection code. The reboot is serial and slow here.
#def reque_and_resurrect():
#    run_module("/aws_EC2/sequential_master_modules/module2e_reque_and_resurrect_Phase3.py")

#### This is module2e for the Phase3 reque and resurrection code. This version2 is multi-threaded reboot code prior to the hand off to module 2f below
def reque_and_resurrect():
    run_module("/aws_EC2/sequential_master_modules/module2e_reque_and_resurrect_Phase3_version2.py")


##### This is module2f for the Phase3 resurrection_intall_tomcat worker thread function
#def resurrection_install_tomcat():
#    run_module("/aws_EC2/sequential_master_modules/module2f_resurrection_install_tomcat.py")    

##### This is module2f for the Phase3 resurrection_intall_tomcat worker thread function. THis is the multi-threaded version
#def resurrection_install_tomcat():
#    run_module("/aws_EC2/sequential_master_modules/module2f_resurrection_install_tomcat_multi-threaded.py")

#### This is module2f for the Phase3 resurrection_intall_tomcat worker thread function. THis is the multi-threaded version and supports ghost ips
def resurrection_install_tomcat():
    run_module("/aws_EC2/sequential_master_modules/module2f_resurrection_install_tomcat_multi-threaded_version2.py")




## modules 3-11:

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
    process1 = multiprocessing.Process(target=restart_ec_multiple_instances, name="Process1: restart_ec_multiple_instances")
    process1.start()
    process1.join()

    process2 = multiprocessing.Process(target=install_tomcat_on_instances, name="Process2: install_tomcat_on_instances")
    process2.start()
    process2.join()

    ### Temporarily comment out modules 2b through 2f from running for the SSH no SYN issue with AWS SG rule revoke
    process2b = multiprocessing.Process(target=post_ghost_analysis, name="Process2b: post_ghost_analysis")
    process2b.start()
    process2b.join()

    process2c = multiprocessing.Process(target=post_aggregate_registry_analysis, name="Process2c: post_aggregate_registry_analysis")
    process2c.start()
    process2c.join()


    process2d = multiprocessing.Process(target=resurrection_gatekeeper, name="Process2d: resurrection_gatekeeper")
    process2d.start()
    process2d.join()

    process2e = multiprocessing.Process(target=reque_and_resurrect, name="Process2e: reque_and_resurrect")
    process2e.start()
    process2e.join()

    process2f = multiprocessing.Process(target=resurrection_install_tomcat, name="Process2f: resurrection_install_tomcat")
    process2f.start()
    process2f.join()



#    process3 = multiprocessing.Process(target=save_instance_ids_and_security_group_ids, name="Process3: save_instance_ids_and_security_group_ids")
#    process3.start()
#    process3.join()
#
#    process4 = multiprocessing.Process(target=create_application_load_balancer, name="Process4: create_application_load_balancer")
#    process4.start()
#    process4.join()
#
#    process5 = multiprocessing.Process(target=ssl_listener_with_route53, name="Process5: ssl_listener_with_route53")
#    process7 = multiprocessing.Process(target=elastic_beanstalk, name="Process7: elastic_beanstalk")
#    process8 = multiprocessing.Process(target=rds_and_security_group, name="Process8: rds_and_security_group")
#
#    process5.start()
#    process7.start()
#    process8.start()
#
#    process5.join()
#    process7.join()
#    process8.join()
#
#
#
#
#
#    process6 = multiprocessing.Process(target=wget_debug, name="Process6: wget_debug")
#    process9 = multiprocessing.Process(target=jumphost_for_rds_mysql_client, name="Process9: jumphost_for_rds_mysql_client")
#    process10 = multiprocessing.Process(target=wget_for_elastic_beanstalk_alb, name="Process10: wget_for_elastic_beanstalk_alb")
#    process11 = multiprocessing.Process(target=https_wget_for_elastic_beanstalk_alb, name="Process11: https_wget_for_elastic_beanstalk_alb")
#
#
#
#
#    process6.start()
#    process9.start()
#    process10.start()
#    process11.start()
#
#
#    process6.join()
#    process9.join()
#    process10.join()
#    process11.join()
#





if __name__ == "__main__":
    main()



