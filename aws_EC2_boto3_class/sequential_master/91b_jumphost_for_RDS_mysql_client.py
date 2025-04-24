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
db_instance_identifier = 'my-rds-instance'
db_instance_class = 'db.t2.micro'
db_engine = 'mysql'
db_name = 'mydatabase'

db_master_username = os.getenv("DB_USERNAME")
db_master_password = os.getenv("DB_PASSWORD")  # Replace with your desired root password

# Retrieve the security_group_id from the security_group_config.json file
with open('security_group_config.json', 'r') as f:
    security_group_config = json.load(f)
    security_group_id = security_group_config['GroupId']

# Initialize the EC2 client using the session
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)
ec2_client = session.client('ec2')

# Launch an EC2 instance named RDS_jumphost with the keypair
try:
    ec2_response = ec2_client.run_instances(
        ImageId=image_id,
        InstanceType=instance_type,
        KeyName='generic_keypair_for_python_testing',
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[security_group_id],
        #IamInstanceProfile={
        #    'Name': instance_profile_name
        #},
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': 'RDS_jumphost'
                    }
                ]
            }
        ]
    )
    ec2_instance_id = ec2_response['Instances'][0]['InstanceId']
    print(f"EC2 instance RDS_jumphost ({ec2_instance_id}) launched successfully.")
except ClientError as e:
    print(f"Error launching EC2 instance RDS_jumphost: {e}")

# Wait for the EC2 instance to be in running state
while True:
    ec2_instance = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])
    ec2_instance_status = ec2_instance['Reservations'][0]['Instances'][0]['State']['Name']

    if ec2_instance_status == 'running':
        break

    print(f"Waiting for EC2 instance RDS_jumphost to be in running state... Current status: {ec2_instance_status}")
    time.sleep(10)

print(f"EC2 instance RDS_jumphost is now running.")

# SSH into the EC2 instance and configure it with MySQL client using paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Replace with the actual public DNS name of the EC2 instance
ec2_instance_dns = ec2_instance['Reservations'][0]['Instances'][0]['PublicDnsName']

# Load the private key file
key = paramiko.RSAKey(filename='EC2_generic_key.pem')

# Define SSH details
port = 22
username = 'ubuntu'
key_path = 'EC2_generic_key.pem'

# Connect to the EC2 instance
ssh.connect(hostname=ec2_instance_dns, username=username, pkey=key)

# Commands to install MySQL client
commands = [
    'sudo DEBIAN_FRONTEND=noninteractive apt update -y',
    'sudo DEBIAN_FRONTEND=noninteractive apt install -y mysql-client',
]

# Execute the commands on the EC2 instance
for command in commands:
    stdin, stdout, stderr = ssh.exec_command(command)
    print(stdout.read().decode())
    print(stderr.read().decode())

# Close the SSH connection
ssh.close()

print("MySQL client installed on EC2 instance RDS_jumphost.")


# test
