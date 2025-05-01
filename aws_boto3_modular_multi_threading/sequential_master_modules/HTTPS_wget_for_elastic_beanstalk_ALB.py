import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
import json
import sys
# for multi-threading
import botocore.exceptions
# for multi-threading
import threading

# Load environment variables from the .env file
load_dotenv()

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")  # Corrected the environment variable name
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
    print(f"Launched wget2 HTTPS EC2 instance with ID: {instance_id}")
    sys.stdout.flush()
except Exception as e:
    print(f"Error launching wget2 HTTPS EC2 instance: {e}")
    sys.stdout.flush()
    exit(1)

# Function to wait for instance to be in running state and pass status checks
instance_ready_event = threading.Event() # for multi-threading
# also add this as an argument for wait_for_instance_running for proper scope. See below
def wait_for_instance_running(instance_id, ec2_client, instance_ready_event):
    import sys # added for multi-threading
    import botocore.exceptions # added for multi-threading
    import time # added for multi-threading
    while True:
        try:
            instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
            print(f"wget2 HTTPS Instance status: {instance_status}")
            sys.stdout.flush()
        
            #if (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running' and
            #    instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and
            #    instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok'):
            #    print(f"wget2 HTTPS Instance {instance_id} is now running and has passed status checks.")
            #    sys.stdout.flush()
            #    instance_ready_event.set()  # Signal that the instance is ready for multi-threading
            #    break
            #else:
            #    print(f"Waiting for wget2 HTTPS instance {instance_id} to be in running state and pass status checks...")
            #    sys.stdout.flush()
            #    time.sleep(10)




            if instance_status['InstanceStatuses']:
                if (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running' and
                    instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and
                    instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok'):
                    print(f"wget2 HTTPS Instance {instance_id} is now running and has passed status checks.")
                    sys.stdout.flush()
                    instance_ready_event.set()  # Signal that the instance is ready for multi-threading
                    break
                else:
                    print(f"Waiting for wget2 HTTPS instance {instance_id} to be in running state and pass status checks...")
                    sys.stdout.flush()
                    time.sleep(10)
            else:
                print(f"No status available for wget2 HTTPS instance {instance_id}. Waiting...")
                sys.stdout.flush()
                time.sleep(10)

        # edited for multi-threading:
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                print(f"Instance ID {instance_id} not found. Retrying...")
                sys.stdout.flush()
                time.sleep(10)
            else:
                print(f"Error checking wget2 HTTPS instance status: {e}")
                sys.stdout.flush()
                time.sleep(10)
        except Exception as e:
            print(f"Error checking wget2 HTTPS instance status: {e}")
            sys.stdout.flush()
            time.sleep(10)
            

# Wait for the instance to be in running state and pass status checks
wait_for_instance_running(instance_id, my_ec2, instance_ready_event)   # add the instance_ready_event to the function call as well for multi-threading case

# Wait for the instance to be ready before proceeding
# added for multi-threading
instance_ready_event.wait()


# Retrieve instance details including DNS and public IP
try:
    instance_description = my_ec2.describe_instances(InstanceIds=[instance_id])
    instance_dns = instance_description['Reservations'][0]['Instances'][0].get('PublicDnsName', '')
    instance_ip = instance_description['Reservations'][0]['Instances'][0].get('PublicIpAddress', '')
    if not instance_dns:
        print(f"wget2 HTTPS instance: Public DNS name not available, using Public IP: {instance_ip}")
        sys.stdout.flush()
    else:
        print(f"wget2 HTTPS Instance DNS: {instance_dns}")
        sys.stdout.flush()
except Exception as e:
    print(f"Error retrieving wget2 HTTPS instance details: {e}")
    sys.stdout.flush()
    exit(1)

# Function to install wget and run the stress test script on the instance
def install_wget_and_run_script(instance_address, key_path, beanstalk_url):
    import paramiko  # added for multi-threading. Similar to the other function above. Scope is much different
    # when converting to the multi-threading for the functions in this module.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(5):
        try:
            print(f"Attempting to connect to wget2 HTTPS {instance_address} (Attempt {attempt + 1})")
            sys.stdout.flush()
            ssh.connect(instance_address, port=22, username='ubuntu', key_filename=key_path)
            break
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"Connection failed to wget2 HTTPS instance: {e}")
            sys.stdout.flush()
            time.sleep(10)
    else:
        print(f"Failed to connect to wget2 HTTPS {instance_address} after multiple attempts")
        sys.stdout.flush()
        return False

    print(f"Connected to wget2 HTTPS {instance_address}. Executing commands...")
    sys.stdout.flush()

    commands = [
        "sudo DEBIAN_FRONTEND=noninteractive apt update",    
        "sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install wget -y",
        f"echo 'while true; do wget -q -O- https://elasticloadbalancer.holinessinloveofchrist.com; done' > stress_test.sh",
        "chmod +x stress_test.sh"
    ]
    
    for command in commands:
        print(f"Executing command on wget2 HTTPS instance: {command}")
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()

        # Check if wget is already installed and proceed if it is
        if "wget is already the newest version" in stdout_output or "wget is already installed" in stdout_output:
            print("wget is already installed on wget2 HTTPS instance. Proceeding with the stress test script.")
            sys.stdout.flush()
            continue

        print(f"STDOUT: {stdout_output}")
        sys.stdout.flush()
        print(f"STDERR: {stderr_output}")
        sys.stdout.flush()

        if stderr_output.strip() and "WARNING: apt does not have a stable CLI interface." not in stderr_output:
            print(f"Error executing command on wget2 HTTPS instance {instance_address}: {stderr_output}")
            sys.stdout.flush()
            stdin.close()
            stdout.close()
            stderr.close()
            ssh.close()
            return False
        
        time.sleep(10)

    # Execute the stress test script without printing its output
    ssh.exec_command("./stress_test.sh")

    stdin.close()
    stdout.close()
    stderr.close()

    transport = ssh.get_transport()
    if transport is not None:
        transport.close()
    
    print(f"Installation completed on wget2 HTTPS instance {instance_address}")
    sys.stdout.flush()
    print(f"wget2 HTTPS Instance ID {instance_id} is sending wget2 HTTPS traffic.")
    sys.stdout.flush()
    return True

# Path to your SSH key file (replace with your actual key file path)
key_file_path = 'EC2_generic_key.pem'

# Load the Elastic Beanstalk URL from the JSON file created by the first script
with open('beanstalk_environment.json', 'r') as f:
    beanstalk_data = json.load(f)

# Print out the contents of the JSON file
print("Contents of beanstalk_environment.json:")
print(json.dumps(beanstalk_data, indent=4))


beanstalk_url = beanstalk_data['CNAME']

# Install wget and run the stress test script on the instance
install_wget_and_run_script(instance_dns if instance_dns else instance_ip, key_file_path, beanstalk_url)

print(f"wget2 HTTPS EC2 instance {instance_id} is created and stress traffic script is running.")
sys.stdout.flush()

## NOTE: with the addition of Route53 hosted zone for this setup (for https cert), can now
## use elasticloadbalancer.holinessinloveofchrist.com URL for both HTTP and HTTPS traffic. Will add that 
## to this script so can test both at the same time.

