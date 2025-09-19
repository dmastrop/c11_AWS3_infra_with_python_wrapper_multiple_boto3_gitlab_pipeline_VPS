# This is the mutli-processing version of the multi-threaded version
# All 11 modules are included



import multiprocessing
import logging

logging.basicConfig(level=logging.CRITICAL, format='%(processName)s: %(message)s')

def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    with open(module_script_path) as f:
        code = f.read()
    exec(code, globals())
    logging.critical(f"Completed module script: {module_script_path}")



#def run_module(module_script_path):
#    logging.critical(f"Starting module script: {module_script_path}")
#    with open(module_script_path) as f:
#        code = f.read()
#    exec(code, globals())
#    if 'main' in globals():
#        main()  # <-- This is the key fix
#    logging.critical(f"Completed module script: {module_script_path}")


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


#### THIS IS THE MODULE2 SCRIPT with wrapper code for command agnotic approach to support bash and bash-like commands, etc.
def install_tomcat_on_instances():
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_zz_patch7c_process_aggregator_write_to_disk_watchdog_debug_patch8_4c1.py")



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



# test76
