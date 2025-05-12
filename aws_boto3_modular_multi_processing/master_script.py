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

def restart_ec_multiple_instances():
    run_module("/aws_EC2/sequential_master_modules/restart_the_EC_multiple_instances_with_client_method_DEBUG.py")





# this one will run with the mutli-processing chnanges to the module2 with 6 processes and 6 threads per process
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py")

# this one will run without the multi-processing changes to the module2
#def install_tomcat_on_instances():
#    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_ORIGINAL_without_main.py")

# this one will run wiht multi-processing chnages to the module2 with 8 processes and 12 threads per process
def install_tomcat_on_instances():
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3_8_and_12.py")





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

