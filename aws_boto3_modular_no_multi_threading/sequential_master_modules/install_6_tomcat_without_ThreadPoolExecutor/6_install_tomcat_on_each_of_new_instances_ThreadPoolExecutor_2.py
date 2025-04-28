import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables from the .env file
load_dotenv()

# Set variables
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
exclude_instance_id = 'i-0ddbf7fda9773252b'

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
security_group_ids = []
instance_ids = []
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        if instance['InstanceId'] != exclude_instance_id:
            public_ips.append(instance['PublicIpAddress'])
            instance_ids.append(instance['InstanceId'])
            for sg in instance['SecurityGroups']:
                security_group_ids.append(sg['GroupId'])

# Define SSH details
port = 22
username = 'ubuntu'
key_path = 'EC2_generic_key.pem'

# Commands to install Tomcat server
commands = [
    'sudo DEBIAN_FRONTEND=noninteractive apt update -y',
    'sudo DEBIAN_FRONTEND=noninteractive apt install -y tomcat9',
    'sudo systemctl start tomcat9',
    'sudo systemctl enable tomcat9'
]

# Add a security group rule to allow access to port 80
for sg_id in set(security_group_ids):
    try:
        my_ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
    except my_ec2.exceptions.ClientError as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print(f"Rule already exists for security group {sg_id}")
        else:
            raise

def wait_for_instance_running(instance_id, ec2_client):
    instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
    while (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] != 'running' or
           instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] != 'ok' or
           instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] != 'ok'):
        print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
        time.sleep(10)
        instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])


# Make the ssh.connect a function that can be used with the ThreadPoolExecutor
def install_tomcat(ip, instance_id):
    wait_for_instance_running(instance_id, my_ec2)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(5):
        try:
            print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")
            ssh.connect(ip, port, username, key_filename=key_path)
            break
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"Connection failed: {e}")
            time.sleep(10)
    else:
        print(f"Failed to connect to {ip} after multiple attempts")
        return

    print(f"Connected to {ip}. Executing commands...")
    for command in commands:
        for attempt in range(3):
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout_output = stdout.read().decode()
            stderr_output = stderr.read().decode()
            print(f"Executing command: {command}")
            print(f"STDOUT: {stdout_output}")
            print(f"STDERR: {stderr_output}")
            if "E: Package 'tomcat9' has no installation candidate" not in stderr_output:
                break
            print(f"Retrying command: {command} (Attempt {attempt + 1})")
            time.sleep(10)
        stdin.close()
        stdout.close()
        stderr.close()
    ssh.close()
    transport = ssh.get_transport()
    if transport is not None:
        transport.close()
    print(f"Installation completed on {ip}")

# Use ThreadPoolExecutor to run installations in parallel
with ThreadPoolExecutor(max_workers=len(public_ips)) as executor:
    futures = [executor.submit(install_tomcat, ip, instance_id) for ip, instance_id in zip(public_ips, instance_ids)]
    for future in as_completed(futures):
        future.result()

print("Script execution completed.")

