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
# Use the security_group_id_RDS that is in the security_group_config_RDS.json file now. This is to 
# decouple from the beanstalk environment/security group.
with open('security_group_config_RDS.json', 'r') as f:
    security_group_config_RDS = json.load(f)
    security_group_id_RDS = security_group_config_RDS['SecurityGroupId']

# Initialize the EC2 client using the session
print("Initializing EC2 client...")
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)
ec2_client = session.client('ec2')
iam_client = session.client('iam')
print("EC2 client initialized.")


# Check if the outbound rule already exists
try:
    security_group_RDS = ec2_client.describe_security_groups(GroupIds=[security_group_id_RDS])
    existing_permissions = security_group_RDS['SecurityGroups'][0]['IpPermissionsEgress']
    rule_exists = any(
        perm['IpProtocol'] == 'tcp' and perm['FromPort'] == 0 and perm['ToPort'] == 65535 and perm['IpRanges'][0]['CidrIp'] == '0.0.0.0/0'
        for perm in existing_permissions
    )

    if not rule_exists:
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
        print(f"Outbound rule added to security group {security_group_id_RDS} successfully.")
    else:
        print(f"Outbound rule already exists in security group {security_group_id_RDS}.")
except ClientError as e:
    print(f"Error checking/adding outbound rule to security group: {e}")
    sys.exit(1)





# Create a new IAM role for the jumphost with the specified policies
role_name = 'jumphost-role'
assume_role_policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

try:
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )
    print(f"IAM role {role_name} created successfully.")
except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
        print(f"IAM role {role_name} already exists.")
    else:
        print(f"Error creating IAM role {role_name}: {e}")
        sys.exit(1)

# Attach the RDS policy to the new role
rds_policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "rds-db:connect"
            ],
            "Resource": [
                "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABCDEFGHIJKL01234/db_user"
            ]
        }
    ]
}

try:
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='RDSConnectPolicy',
        PolicyDocument=json.dumps(rds_policy_document)
    )
    print(f"RDS policy attached to IAM role {role_name} successfully.")
except ClientError as e:
    print(f"Error attaching RDS policy to IAM role {role_name}: {e}")
    sys.exit(1)

# Attach the default EC2 policy to the new role for SSH and basic operations
default_ec2_policy_arn = 'arn:aws:iam::aws:policy/AmazonEC2FullAccess'

try:
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=default_ec2_policy_arn
    )
    print(f"Default EC2 policy attached to IAM role {role_name} successfully.")
except ClientError as e:
    print(f"Error attaching default EC2 policy to IAM role {role_name}: {e}")
    sys.exit(1)

# Create an instance profile and add the new role to it
instance_profile_name = 'jumphost-instance-profile'

try:
    iam_client.create_instance_profile(
        InstanceProfileName=instance_profile_name
    )
    print(f"Instance profile {instance_profile_name} created successfully.")
except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
        print(f"Instance profile {instance_profile_name} already exists.")
    else:
        print(f"Error creating instance profile: {e}")
        sys.exit(1)

# Detach any existing role from the instance profile
try:
    instance_profile = iam_client.get_instance_profile(
        InstanceProfileName=instance_profile_name
    )
    if instance_profile['InstanceProfile']['Roles']:
        existing_role_name = instance_profile['InstanceProfile']['Roles'][0]['RoleName']
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=instance_profile_name,
            RoleName=existing_role_name
        )
        print(f"Detached existing role {existing_role_name} from instance profile {instance_profile_name}.")
except ClientError as e:
    print(f"Error detaching existing role from instance profile: {e}")
    sys.exit(1)

# Add the new role to the instance profile
try:
    iam_client.add_role_to_instance_profile(
        InstanceProfileName=instance_profile_name,
        RoleName=role_name
    )
    print(f"Role {role_name} added to instance profile {instance_profile_name} successfully.")
except ClientError as e:
    print(f"Error adding role to instance profile: {e}")
    sys.exit(1)

# Retrieve the ARN of the instance profile
try:
    instance_profile = iam_client.get_instance_profile(
        InstanceProfileName=instance_profile_name
    )
    instance_profile_arn = instance_profile['InstanceProfile']['Arn']
    print(f"Instance profile ARN: {instance_profile_arn}")
except ClientError as e:
    print(f"Error retrieving instance profile ARN: {e}")
    sys.exit(1)

# Launch an EC2 instance named RDS_jumphost with the keypair and new instance profile
print("Launching EC2 instance RDS_jumphost...")
try:
    ec2_response = ec2_client.run_instances(
        ImageId=image_id,
        InstanceType=instance_type,
        KeyName='generic_keypair_for_python_testing',
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[security_group_id_RDS],
        IamInstanceProfile={
            'Arn': instance_profile_arn
        },
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{
                'Key': 'Name',
                'Value': 'RDS_jumphost'
            }]
        }]
    )
    ec2_instance_id = ec2_response['Instances'][0]['InstanceId']
    print(f"EC2 instance RDS_jumphost ({ec2_instance_id}) launched successfully.")
except ClientError as e:
    print(f"Error launching EC2 instance RDS_jumphost: {e}")
    sys.exit(1)

# Wait for the EC2 instance to be in running state and status checks to pass
# new code is added here
#  the describe_instance_status call is returning an empty list for InstanceStatuses, which can happen if the instance status checks haven't started yet. To handle this, we can add a check to ensure the list is not empty before accessing its elements.
print("Waiting for EC2 instance RDS_jumphost to be in running state and status checks to pass...")
while True:
    try:
        ec2_instance = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])
        ec2_instance_status = ec2_instance['Reservations'][0]['Instances'][0]['State']['Name']
        status_checks = ec2_client.describe_instance_status(InstanceIds=[ec2_instance_id])
        if status_checks['InstanceStatuses']:
            instance_status_check = status_checks['InstanceStatuses'][0]['InstanceStatus']['Status']
            system_status_check = status_checks['InstanceStatuses'][0]['SystemStatus']['Status']

            if ec2_instance_status == 'running' and instance_status_check == 'ok' and system_status_check == 'ok':
                print(f"EC2 instance RDS_jumphost is now running and status checks passed.")
                break

        print(f"Current status: {ec2_instance_status}. Waiting for EC2 instance to be in running state and status checks to pass...")
        time.sleep(10)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            print(f"Instance ID {ec2_instance_id} not found. Retrying...")
            time.sleep(10)
        else:
            print(f"Error describing instances: {e}")
            sys.exit(1)

# Wait for the instance to be fully initialized
print("Waiting for EC2 instance to be fully initialized...")
time.sleep(60)  # Add a delay to ensure the instance is fully initialized

# SSH into the EC2 instance and configure it with MySQL client using paramiko
print("Connecting to EC2 instance via SSH...")
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
try:
    ssh.connect(hostname=ec2_instance_dns, username=username, pkey=key)
    print("SSH connection established.")
except Exception as e:
    print(f"Error connecting to EC2 instance via SSH: {e}")
    sys.exit(1)

# Commands to install MySQL client
commands = [
    'sudo DEBIAN_FRONTEND=noninteractive apt update -y',
    'sudo DEBIAN_FRONTEND=noninteractive apt install -y mysql-client',
]

# Execute the commands on the EC2 instance
print("Executing commands to install MySQL client...")
for command in commands:
    stdin, stdout, stderr = ssh.exec_command(command)
    print(stdout.read().decode())
    print(stderr.read().decode())





# Configure the RDS server with the specified commands
rds_endpoint = 'my-rds-instance.cmfayq2u499p.us-east-1.rds.amazonaws.com'
mysql_commands = [
    "echo 'Creating users table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) NOT NULL);\"",
    "echo 'Inserting Alice into users table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');\"",
    "echo 'Inserting Bob into users table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"INSERT INTO users (name, email) VALUES ('Bob', 'bob@example.com');\"",
    "echo 'Creating index on email column:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"CREATE INDEX idx_email ON users(email);\"",
    "echo 'Creating new user:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"CREATE USER 'newuser'@'%' IDENTIFIED BY 'password';\"",
    "echo 'Granting privileges to new user:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"GRANT ALL PRIVILEGES ON mydatabase.* TO 'newuser'@'%';\"",
    "echo 'Flushing privileges:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"FLUSH PRIVILEGES;\"",
    "echo 'Showing mysql.user table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"SELECT * FROM mysql.user\\G;\"",
    "echo 'Showing mysql.db table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"SELECT * FROM mysql.db\\G;\"",
    "echo 'Showing tables in database:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"show tables;\"",
    "echo 'Selecting all from users table:'",
    f"mysql -h {rds_endpoint} -u {db_master_username} -p'{db_master_password}' {db_name} -e \"SELECT * FROM users;\""
]



print("Configuring RDS server with MySQL commands...")
for command in mysql_commands:
    stdin, stdout, stderr = ssh.exec_command(command)
    print(stdout.read().decode())
    print(stderr.read().decode())

# Close the SSH connection
#ssh.close()

# Make sure to close the connection properly. 

#Ensure Proper Closure of SSH Connection: Make sure the SSH connection is properly closed after all commands are executed. This can help prevent the `NoneType` error.
# AND Check for `None` Before Accessing Attributes**: Modify the script to check if the `Transport` object is `None` before attempting to access its attributes.
if ssh.get_transport() is not None:
    time.sleep(2)  # Add a slight delay before closing the connection
    ssh.close()

print("SSH connection closed.")
print("MySQL client installed on EC2 instance RDS_jumphost.")
print("RDS server configured with MySQL commands.")



# test2
