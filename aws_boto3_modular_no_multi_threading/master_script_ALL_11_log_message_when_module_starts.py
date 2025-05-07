import importlib

# non-multi-threading and all 11 modules
modules = [
    "restart_the_EC_multiple_instances_with_client_method_DEBUG",
    #"save_instance_ids_and_security_group_ids_to_json_file",
    # note move the save_instance module to after the install tomcat. Install tomcat ensures that the 
    # instances are all up and running. We don't need to add a delay in save_instance if it is moved after 
    # install_tomcat
    "install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3",
    "save_instance_ids_and_security_group_ids_to_json_file",
    "create_application_load_balancer_for_EC2_tomcat9_instances_json_pretty_format_BY_ALB_NAME",
    "SSL_listener_with_Route53_for_ACM_validation_with_CNAME_automated_3_BY_ALB_NAME",
    "wget_debug4",
    "Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS",
    "RDS_and_security_group_json",
    "jumphost_for_RDS_mysql_client_NEW3",
    "wget_for_elastic_beanstalk_ALB",
    "HTTPS_wget_for_elastic_beanstalk_ALB"
]

def main():
    for module_name in modules:
        print(f"Executing module: {module_name}")
        module = importlib.import_module(f"sequential_master_modules.{module_name}")

if __name__ == "__main__":
    main()

