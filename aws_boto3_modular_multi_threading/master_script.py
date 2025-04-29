import threading
from sequential_master_modules import Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS
from sequential_master_modules import RDS_and_security_group_json
from sequential_master_modules import jumphost_for_RDS_mysql_client_NEW3
from sequential_master_modules import wget_for_elastic_beanstalk_ALB
from sequential_master_modules import HTTPS_wget_for_elastic_beanstalk_ALB

def run_module(module):
    # This function will run the module's executable code
    pass

def main():
    # Create threads for the first two modules
    thread1 = threading.Thread(target=run_module, args=(Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS,))
    thread2 = threading.Thread(target=run_module, args=(RDS_and_security_group_json,))

    # Start the first two threads
    thread1.start()
    thread2.start()

    # Wait for the first two threads to complete
    thread1.join()
    thread2.join()

    # Create threads for the last three modules
    thread3 = threading.Thread(target=run_module, args=(jumphost_for_RDS_mysql_client_NEW3,))
    thread4 = threading.Thread(target=run_module, args=(wget_for_elastic_beanstalk_ALB,))
    thread5 = threading.Thread(target=run_module, args=(HTTPS_wget_for_elastic_beanstalk_ALB,))

    # Start the last three threads
    thread3.start()
    thread4.start()
    thread5.start()

    # Wait for the last three threads to complete
    thread3.join()
    thread4.join()
    thread5.join()

if __name__ == "__main__":
    main()

