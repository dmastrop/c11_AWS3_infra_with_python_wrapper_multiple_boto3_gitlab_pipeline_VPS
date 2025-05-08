import threading
import logging

logging.basicConfig(level=logging.CRITICAL, format='%(threadName)s: %(message)s')


# Comment out the imports because exec is getting modules from string full path and NOT module object!!

#from sequential_master_modules import Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS
#from sequential_master_modules import RDS_and_security_group_json
#from sequential_master_modules import jumphost_for_RDS_mysql_client_NEW3
#from sequential_master_modules import wget_for_elastic_beanstalk_ALB
#from sequential_master_modules import HTTPS_wget_for_elastic_beanstalk_ALB


# Note that using the exec function because all the modules are standalone and do not have just a single function
# If the entire module code was in a function we could invoke with module() where module is the name of the function in the module.
# the exec function below will get the entire block of code as a string
# The `exec` function executes the string of code read from the file. This means the entire script is executed within the context of the `run_module` function.

# NOTE: The `exec` function expects a string, bytes, or os.PathLike object, not a module object. Cannot simply
# pass a module object but need full path to the module script. Since this is docker container it has to be
# path defined by HOME DIRECTORY in the container not the pipeline source code.
# define new variable module_script_path instead of module_script object from the imports above

# NOTE: need to comment out the import modules above. If these are left in the main() below will execute them serially and then the threads will run and everything will run twice!!

# Major rewrite of the code to support all 11 modules in multi-threaded setup. Prior to this tested with 5 of the modules
# Note that the first 6 modules have chagnes as well to support port from manual sequential execution to module execution
# We can run 6,7,8 and 9,10,11 together in parallel. Use the join to ensure proper throttling of the thread blocks.

def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    exec(open(module_script_path).read())
    logging.critical(f"Completed module script: {module_script_path}")


def main():


    thread1 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/restart_the_EC_multiple_instances_with_client_method_DEBUG.py",))

    thread1.start()
    thread1.join()

    thread2 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py",))

    thread2.start()
    thread2.join()



    thread3 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/save_instance_ids_and_security_group_ids_to_json_file.py",))

    thread3.start()
    thread3.join()


    thread4 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/create_application_load_balancer_for_EC2_tomcat9_instances_json_pretty_format_BY_ALB_NAME.py",))

    thread4.start()
    thread4.join()

    thread5 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/SSL_listener_with_Route53_for_ACM_validation_with_CNAME_automated_3_BY_ALB_NAME.py",))

    thread5.start()
    thread5.join()


    thread6 = threading.Thread(target=run_module, args=("/aws_EC2/ sequential_master_modules/wget_debug4.py",))
    thread7 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS.py",))
    thread8 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/ RDS_and_security_group_json.py",))
    
    thread6.start()
    thread7.start()
    thread8.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread6.join()
    thread7.join()
    thread8.join()



    thread9 = threading.Thread(target=run_module, args=("/aws_EC2/ sequential_master_modules/wget_debug4.py",))
    thread10 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS.py",))
    thread11 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/ RDS_and_security_group_json.py",))
    
    thread9.start()
    thread10.start()
    thread11.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread9.join()
    thread10.join()
    thread11.join()


    

if __name__ == "__main__":
    main()

