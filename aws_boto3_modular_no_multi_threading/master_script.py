# master_script.py
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
