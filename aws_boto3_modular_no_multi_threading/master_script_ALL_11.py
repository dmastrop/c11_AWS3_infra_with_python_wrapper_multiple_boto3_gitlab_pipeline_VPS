# master_script.py
# non-multi-threading and all 11 modules
from sequential_master_modules import restart_the_EC_multiple_instances_with_client_method_DEBUG.py
from sequential_master_modules import save_instance_ids_and_security_group_ids_to_json_file.py
from sequential_master_modules import install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py
from sequential_master_modules import create_application_load_balancer_for_EC2_tomcat9_instances_json_pretty_format_BY_ALB_NAME.py
from sequential_master_modules import SSL_listener_with_Route53_for_ACM_validation_with_CNAME_automated_3_BY_ALB_NAME.py
__init__.py
from sequential_master_modules import wget_debug4.py



from sequential_master_modules import Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS
from sequential_master_modules import RDS_and_security_group_json
from sequential_master_modules import jumphost_for_RDS_mysql_client_NEW3
from sequential_master_modules import wget_for_elastic_beanstalk_ALB
from sequential_master_modules import HTTPS_wget_for_elastic_beanstalk_ALB


# Note the modules above are fully executable and standlone wiht many functions in each one of them. Thus no need to call the multiple functions from main.  


#def main():
#    beanstalk_setup.create_environment()
#    rds_setup.create_rds_instance()
#    jumphost_setup.configure_jumphost()

def main():
# no need to do the function calls from the imported moudles as they are standlone. We are just using this for sequential execution. Will work on multi-threading and multi-processing later on....
    pass

if __name__ == "__main__":
    main()

# test
