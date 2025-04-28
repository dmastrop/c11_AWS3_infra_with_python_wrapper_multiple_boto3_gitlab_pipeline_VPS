import boto3
from dotenv import load_dotenv
import os
import paramiko
import time

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

# Establish a session with AWS
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)

# Create an EC2 client
my_ec2 = session.client('ec2')

# Launch an EC2 instance with error handling
try:
    instances = my_ec2.run_instances(
        ImageId=image_id,
        InstanceType=instance_type,
        KeyName=key_name,
        MinCount=1,
        MaxCount=1
    )
    instance_id = instances['Instances'][0]['InstanceId']
    instance_dns = instances['Instances'][0]['PublicDnsName']
    print(f"Launched EC2 instance with ID: {instance_id} and DNS: {instance_dns}")
except Exception as e:
    print(f"Error launching EC2 instance: {e}")
    exit(1)

# Function to wait for instance to be in running state and pass status checks
def wait_for_instance_running(instance_id, ec2_client):
    instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
    while (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] != 'running' or
           instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] != 'ok' or
           instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] != 'ok'):
        print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
        time.sleep(10)
        instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
    print(f"Instance {instance_id} is now running and has passed status checks.")

# Wait for the instance to be in running state and pass status checks
wait_for_instance_running(instance_id, my_ec2)

# Function to install wget and run the stress test script on the instance
def install_wget_and_run_script(instance_dns, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(5):
        try:
            print(f"Attempting to connect to {instance_dns} (Attempt {attempt + 1})")
            ssh.connect(instance_dns, port=22, username='ubuntu', key_filename=key_path)
            break
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"Connection failed: {e}")
            time.sleep(10)
    else:
        print(f"Failed to connect to {instance_dns} after multiple attempts")
        return False

    print(f"Connected to {instance_dns}. Executing commands...")
    
    commands = [
        "sudo apt update",
        "sudo apt install wget -y",
        "echo 'while true; do wget -q -O- https://loadbalancer.holinessinloveofchrist.com; done' > stress_test.sh",
        "chmod +x stress_test.sh",
        "./stress_test.sh"
    ]
    
    for command in commands:
        print(f"Executing command: {command}")
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()
        print(f"STDOUT: {stdout_output}")
        print(f"STDERR: {stderr_output}")
        
        if stderr_output.strip():
            print(f"Error executing command on {instance_dns}: {stderr_output}")
            stdin.close()
            stdout.close()
            stderr.close()
            ssh.close()
            return False
        
        time.sleep(10)
    
    stdin.close()
    stdout.close()
    stderr.close()
    ssh.close()
    
    transport = ssh.get_transport()
    if transport is not None:
        transport.close()
    
    print(f"Installation completed on {instance_dns}")
    print(f"Instance ID {instance_id} is sending wget traffic.")
    return True

# Path to your SSH key file (replace with your actual key file path)
key_file_path = 'EC2_generic_key.pem'

# Install wget and run the stress test script on the instance
install_wget_and_run_script(instance_dns, key_file_path)

print(f"EC2 instance {instance_id} is created and stress traffic script is running.")

