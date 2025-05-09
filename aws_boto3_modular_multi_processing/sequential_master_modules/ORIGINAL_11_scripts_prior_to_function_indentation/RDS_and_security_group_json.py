import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
import sys
import json
from botocore.exceptions import ClientError



# Load environment variables from the .env file
load_dotenv()

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")
image_id = os.getenv("image_id")
instance_type = os.getenv("instance_type")
key_name = os.getenv("key_name")
aws_pem_key = 'EC2_generic_key.pem'
hosted_zone_id = 'Z055765416LPH0LA4ZBVA'  # Your Route 53 hosted zone ID
hosted_zone_name = 'elasticloadbalancer.holinessinloveofchrist.com'
# RDS stuff
db_instance_identifier = 'my-rds-instance'
db_instance_class = 'db.t3.micro'
db_engine = 'mysql'
db_name = 'mydatabase'


# add the RDS credentials. These are added to the .gitlab-ci.yml file and piped into the .env file.
# This retrieves them from that file. The raw variables and variables are stored in the gltlab pipeline
# CI/CD variables section
# Make sure the password stored on gitlab pipeline env varaiables is at least 8 characters long
db_master_username = os.getenv("DB_USERNAME")
db_master_password = os.getenv("DB_PASSWORD")  # Replace with your desired root password

#According to AWS documentation, you can only create MySQL version 8.0 DB instances with latest-generation and current-generation DB instance classes [2](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.Support.html).

#Update Instance Class: Switch to a different instance class that is compatible with MySQL 8.0. For example, `db.t3.micro` is often compatible with newer versions of MySQL [3](https://repost.aws/questions/QU1llceoaxT2Or7r4kcWKuDg/why-did-i-get-a-db-creating-error-from-terraform).



# Establish a session with AWS
print("Establishing session with AWS...")
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)
print("Session established.")


# Initialize the EC2 client using the session
ec2_client = session.client('ec2')


# NEW CODE BLOCK to create a new security group security_group_id_RDS for use only with the RDS and jumphost server
# This is to decouple the RDS/jumphost setup from the beanstalk setup because of the Cloudstack dependency that
# a common SG creates.


# Create the new security group for RDS
try:
    response = ec2_client.create_security_group(
        GroupName='RDS_security_group',
        Description='Security group for RDS server and jumphost',
        VpcId='vpc-0a11e68402b1fa2f3'  # Replace with your VPC ID. Use the default VPC
    )
    security_group_id_RDS = response['GroupId']
    print(f"Security group {security_group_id_RDS} created successfully.")
except ClientError as e:
    if 'InvalidGroup.Duplicate' in str(e):
        print("Security group already exists. Retrieving existing security group ID.")
        response = ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['RDS_security_group']}]
        )
        security_group_id_RDS = response['SecurityGroups'][0]['GroupId']
    else:
        print(f"Error creating security group: {e}")
        raise

# Add inbound rules
try:
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id_RDS,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 3306,
                'ToPort': 3306,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    print("Inbound rules added successfully.")
except ClientError as e:
    if 'InvalidPermission.Duplicate' in str(e):
        print("Inbound rules already exist.")
    else:
        print(f"Error adding inbound rules: {e}")
        raise

# Add outbound rules
try:
    ec2_client.authorize_security_group_egress(
        GroupId=security_group_id_RDS,
        IpPermissions=[
            {
               'IpProtocol': 'tcp',
                'FromPort': 0,
                'ToPort': 65535,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    print("Outbound rules added successfully.")
except ClientError as e:
    if 'InvalidPermission.Duplicate' in str(e):
        print("Outbound rules already exist.")
    else:
        print(f"Error adding outbound rules: {e}")
        raise


# Define the security group configuration
security_group_config_RDS = {
    "GroupName": "RDS_security_group",
    "Description": "Security group for RDS server and jumphost",
    "VpcId": "vpc-0a11e68402b1fa2f3",  # Replace with your VPC ID. Use the default VPC.
    "SecurityGroupId": security_group_id_RDS,
    "InboundRules": [
        {
            'IpProtocol': 'tcp',
            'FromPort': 3306,
            'ToPort': 3306,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
    ],
    "OutboundRules": [
        {
            'IpProtocol': 'tcp',
            'FromPort': 0,
            'ToPort': 65535,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }
    ]
}

# Export the configuration to a JSON file
with open('security_group_config_RDS.json', 'w') as json_file:
    json.dump(security_group_config_RDS, json_file, indent=4)

print("Security group configuration exported to security_group_config_RDS.json.")





# Initialize the RDS client using the session.
# Use security_group_id_RDS instead of security_group_id
rds_client = session.client('rds')

# Create the RDS instance
try:
    rds_client.create_db_instance(
        DBInstanceIdentifier=db_instance_identifier,
        DBInstanceClass=db_instance_class,
        Engine=db_engine,
        MasterUsername=db_master_username,
        MasterUserPassword=db_master_password,
        DBName=db_name,
        AllocatedStorage=20,  # Adjust as needed
        BackupRetentionPeriod=7,  # Adjust as needed
        MultiAZ=False,
        PubliclyAccessible=True,
        VpcSecurityGroupIds=[security_group_id_RDS],  # Do not Use the same security group as the load balancer. Use a new security_group_id_RDS as defined above. This is to decouple the beanstalk environment from the RDS and jumphost setup so there is no Cloudformation stack dependency on the RDS/jumphost.
        Tags=[
            {
                'Key': 'Name',
                'Value': 'MyRDSInstance'
            }
        ]
    )
    print(f"RDS instance {db_instance_identifier} created successfully.")
except ClientError as e:
    print(f"Error creating RDS instance: {e}")

# Wait for the RDS instance to be available
while True:
    db_instance = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
    db_instance_status = db_instance['DBInstances'][0]['DBInstanceStatus']

    if db_instance_status == 'available':
        break

    print(f"Waiting for RDS instance to be available... Current status: {db_instance_status}")
    time.sleep(30)

print(f"RDS instance {db_instance_identifier} is now available.")
sys.stdout.flush()

