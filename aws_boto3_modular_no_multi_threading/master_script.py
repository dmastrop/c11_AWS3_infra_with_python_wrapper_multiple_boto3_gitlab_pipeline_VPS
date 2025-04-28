# master_script.py
from sequential_master import 91_Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS
from sequential_master import 91b_RDS_and_security_group_json
from sequential_master import 91c_jumphost_for_RDS_mysql_client_NEW3
from sequential_master import 92_wget_for_elastic_beanstalk_ALB
from sequential_master import 93_HTTPS_wget_for_elastic_beanstalk_ALB


# Note the modules above are fully executable and standlone wiht many functions in each one of them. Thus no need to call the multiple functions from main.  


#def main():
#    beanstalk_setup.create_environment()
#    rds_setup.create_rds_instance()
#    jumphost_setup.configure_jumphost()

def main();
# no need to do the function calls from the imported moudles as they are standlone. We are just using this for sequential execution. Will work on multi-threading and multi-processing later on....


if __name__ == "__main__":
    main()

