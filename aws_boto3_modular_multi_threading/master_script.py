import threading
import logging

logging.basicConfig(level=logging.CRITICAL, format='%(threadName)s: %(message)s')

from sequential_master_modules import Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS
from sequential_master_modules import RDS_and_security_group_json
from sequential_master_modules import jumphost_for_RDS_mysql_client_NEW3
from sequential_master_modules import wget_for_elastic_beanstalk_ALB
from sequential_master_modules import HTTPS_wget_for_elastic_beanstalk_ALB


# Note that using the exec function because all the modules are standalone and do not have just a single function
# If the entire module code was in a function we could invoke with module() where module is the name of the function in the module.
# the exec function below will get the entire block of code as a string
# The `exec` function executes the string of code read from the file. This means the entire script is executed within the context of the `run_module` function.

# NOTE: The `exec` function expects a string, bytes, or os.PathLike object, not a module object. Cannot simply
# pass a module object but need full path to the module script. Since this is docker container it has to be
# path defined by HOME DIRECTORY in the container not the pipeline source code.
# define new variable module_script_path instead of module_script object from the imports above

def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    exec(open(module_script_path).read())
    logging.critical(f"Completed module script: {module_script_path}")


def main():
    # Create and start threads for the first two modules
    #thread1 = threading.Thread(target=run_module, args=(Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS,))
    #thread2 = threading.Thread(target=run_module, args=(RDS_and_security_group_json,))
    #thread1.start()
    #thread2.start()

    thread1 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS.py",))
    thread2 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/RDS_and_security_group_json.py",))
    thread1.start()
    thread2.start()


    # Wait for the first two threads to complete. main() will be in blocking until both of the threads are complete which is why we need to have both thread1.join and thread2.join. Both have to be completed prior to moving onto the next group of threads below.
    thread1.join()
    thread2.join()

    # Create and start threads for the last three modules
    #thread3 = threading.Thread(target=run_module, args=(jumphost_for_RDS_mysql_client_NEW3,))
    #thread4 = threading.Thread(target=run_module, args=(wget_for_elastic_beanstalk_ALB,))
    #thread5 = threading.Thread(target=run_module, args=(HTTPS_wget_for_elastic_beanstalk_ALB,))
    #thread3.start()
    #thread4.start()
    #thread5.start()


    thread3 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/jumphost_for_RDS_mysql_client_NEW3.py",))
    thread4 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/wget_for_elastic_beanstalk_ALB.py",))
    thread5 = threading.Thread(target=run_module, args=("/aws_EC2/sequential_master_modules/HTTPS_wget_for_elastic_beanstalk_ALB.py",))
    thread3.start()
    thread4.start()
    thread5.start()



    # Wait for the last three threads to complete. main() will be blocking until all threads are complete. See above.
    thread3.join()
    thread4.join()
    thread5.join()

if __name__ == "__main__":
    main()

