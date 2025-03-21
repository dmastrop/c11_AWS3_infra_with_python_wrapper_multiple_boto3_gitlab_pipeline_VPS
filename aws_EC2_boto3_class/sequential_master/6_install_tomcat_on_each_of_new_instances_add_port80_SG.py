import boto3
from dotenv import load_dotenv
import os
import paramiko # add this to requirement.txt as not part of standard lib
import time # Import the time module. add this for the ssh retry code below. This is part of standard lib

# test2
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
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        if instance['InstanceId'] != exclude_instance_id:
            public_ips.append(instance['PublicIpAddress'])
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
#for sg_id in set(security_group_ids):
#    my_ec2.authorize_security_group_ingress(
#        GroupId=sg_id,
#        IpPermissions=[
#            {
#                'IpProtocol': 'tcp',
#                'FromPort': 80,
#                'ToPort': 80,
#                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
#            }
#        ]
#    )




# Add a security group rule to allow access to port 80
# add error code if the rule already exists
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

# SSH into each instance and install Tomcat server
for ip in public_ips:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #ssh.connect(ip, port, username, key_filename=key_path)
    
    # Retry logic for SSH connection. Instead of the simple ssh.connect above, with one try and no failure logic
    # add the retry logic below (5 tries with 10 second delay between them).  This is because i am consistently seeing
    # the first ssh to the first ssh EC2 instance failing.   When manually testing to that same instance, ssh works fine
    # so it is not access lists, connectivity, pem key, etc. issues.  This should resolve the issue.
    for attempt in range(5):
        try:
            print(f"Attempting to connect to {ip} (Attempt {attempt + 1})")
            ssh.connect(ip, port, username, key_filename=key_path)
            break
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"Connection failed: {e}")
            time.sleep(10)  # Wait before retrying
    else:
        print(f"Failed to connect to {ip} after multiple attempts")
        continue
    
    print(f"Connected to {ip}. Executing commands...")


    #for command in commands:
        #stdin, stdout, stderr = ssh.exec_command(command)
        #print(f"Executing command: {command}")



        #stdout_output = stdout.read().decode()
        #stderr_output = stderr.read().decode()

   

        #print(f"STDOUT: {stdout_output}")
        #print(f"STDERR: {stderr_output}")
        

    #Explicitly close the files and channel(). This is to address an installation issue of tomcat9
    #from stackoverflow:
    #By explicitly closing the `stdin`, `stdout`, and `stderr` files, you can help ensure that resources are properly cleaned up, which should prevent the `NoneType` error from occurring[1](https://stackoverflow.com/questions/37556888/why-does-paramiko-sporadically-raise-an-exception).

    #stdin.close()
    #stdout.close()
    #stderr.close()


# add the retry code into the command block above to look like this
# This is to attempt to resolve the timing issue with the installation for the first EC2 instance. If this does not resolve
# the issue that are other things that can be added

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


        # Explicitly close the files and channel(). This is to address an installation issue of tomcat9
        # from stackoverflow:
        # By explicitly closing the `stdin`, `stdout`, and `stderr` files, you can help ensure that resources are properly cleaned up, which should prevent the `NoneType` error from occurring[1](https://stackoverflow.com/questions/37556888/why-does-paramiko-sporadically-raise-an-exception).

        stdin.close()
        stdout.close()
        stderr.close()



    ssh.close()

    transport = ssh.get_transport()
    if transport is not None:
        transport.close()  # Ensure the transport is closed
    
    #ssh.get_transport().close()  # Ensure the transport is closed

    #By explicitly closing the `stdin`, `stdout`, and `stderr` files, you can help ensure that resources are properly cleaned up, which should prevent the `NoneType` error from occurring[1](https://stackoverflow.com/questions/37556888/why-does-paramiko-sporadically-raise-an-exception).
    # adding more logic to the transport close for this error: AttributeError: 'NoneType' object has no attribute 'close'

print("Script execution completed.")



