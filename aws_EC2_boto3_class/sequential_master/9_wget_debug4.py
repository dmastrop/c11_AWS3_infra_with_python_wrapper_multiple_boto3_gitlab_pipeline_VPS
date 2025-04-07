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
    print(f"Launched EC2 instance with ID: {instance_id}")
except Exception as e:
    print(f"Error launching EC2 instance: {e}")
    exit(1)

# Function to wait for instance to be in running state and pass status checks
def wait_for_instance_running(instance_id, ec2_client):
    while True:
        try:
            instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
            print(f"Instance status: {instance_status}")
            if (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running' and
                instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and
                instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok'):
                print(f"Instance {instance_id} is now running and has passed status checks.")
                break
            else:
                print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
                time.sleep(10)
        except Exception as e:
            print(f"Error checking instance status: {e}")
            time.sleep(10)

# Wait for the instance to be in running state and pass status checks
wait_for_instance_running(instance_id, my_ec2)

# Retrieve instance details including DNS and public IP
try:
    instance_description = my_ec2.describe_instances(InstanceIds=[instance_id])
    instance_dns = instance_description['Reservations'][0]['Instances'][0].get('PublicDnsName', '')
    instance_ip = instance_description['Reservations'][0]['Instances'][0].get('PublicIpAddress', '')
    if not instance_dns:
        print(f"Public DNS name not available, using Public IP: {instance_ip}")
    else:
        print(f"Instance DNS: {instance_dns}")
except Exception as e:
    print(f"Error retrieving instance details: {e}")
    exit(1)

# Function to install wget and run the stress test script on the instance
def install_wget_and_run_script(instance_address, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(5):
        try:
            print(f"Attempting to connect to {instance_address} (Attempt {attempt + 1})")
            ssh.connect(instance_address, port=22, username='ubuntu', key_filename=key_path)
            break
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"Connection failed: {e}")
            time.sleep(10)
    else:
        print(f"Failed to connect to {instance_address} after multiple attempts")
        return False

    print(f"Connected to {instance_address}. Executing commands...")
    
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
            print(f"Error executing command on {instance_address}: {stderr_output}")
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
    
    print(f"Installation completed on {instance_address}")
    print(f"Instance ID {instance_id} is sending wget traffic.")
    return True

# Path to your SSH key file (replace with your actual key file path)
key_file_path = 'EC2_generic_key.pem'

# Install wget and run the stress test script on the instance
install_wget_and_run_script(instance_dns if instance_dns else instance_ip, key_file_path)

print(f"EC2 instance {instance_id} is created and stress traffic script is running.")

