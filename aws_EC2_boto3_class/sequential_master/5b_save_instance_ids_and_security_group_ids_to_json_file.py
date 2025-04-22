import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys

# Load environment variables from the .env file
load_dotenv()

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")
image_id = os.getenv("image_id")
instance_type = os.getenv("instance_type")
key_name = os.getenv("key_name")
min_count = os.getenv("min_count")
max_count = os.getenv("max_count")
aws_pem_key = os.getenv("AWS_PEM_KEY")

# Define the instance ID to exclude (the EC2 controller)
exclude_instance_id = 'i-0aaaa1aa8907a9b78'

# Establish a session with AWS
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)

# Create an EC2 client
my_ec2 = session.client('ec2')

# Describe the running instances
response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

# Get the public IP addresses and security group IDs of the running instances except the excluded instance ID
public_ips = []
private_ips = []
security_group_ids = []
instance_ids = []
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        if instance['InstanceId'] != exclude_instance_id:
            public_ips.append(instance['PublicIpAddress'])
            private_ips.append(instance['PrivateIpAddress'])
            instance_ids.append(instance['InstanceId'])
            for sg in instance['SecurityGroups']:
                security_group_ids.append(sg['GroupId'])


# Save instance IDs and security group IDs to a file
# The instance_id and the security_group_ids will be needed in the AWS ALB script in a different .py file
data = {
    'instance_ids': instance_ids,
    'security_group_ids': list(set(security_group_ids))
}
with open('instance_ids.json', 'w') as f:
    json.dump(data, f)
