# This version has further optimizations to the install tomcat code. Since there are so many instances, this
# needs to utilize not only the current ThreadPoolExecutor but also wrap the current install_tomcat_on_instances
# function with main that does the following:
# Still use the ThreadPoolExecutor but:
# The script now uses multi-processing to distribute the SSH connections across multiple cores. Each process handles a chunk of instances.
# Continue to use (call) the ThreadPoolExecutor Within each process, the `ThreadPoolExecutor` is used to run installations in parallel, matching the number of CPU cores available.  There are 6 CPU cores on the VPS. So each core will be running
# the ThreadPoolExecutor with a group of installations on each core.
# NOTE that Archlinux suppports multi-processing.



# Move the imports to outside of the functions. This is ok as all functions in this file will now have access to the 
# imported dependencies.

import multiprocessing
import threading
import logging
import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys



logging.basicConfig(level=logging.CRITICAL, format='%(processName)s: %(message)s')



# this function run_module is not used here but in the master python script, but may use this function here at some later
# time
def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    with open(module_script_path) as f:
        code = f.read()
    exec(code, globals())
    logging.critical(f"Completed module script: {module_script_path}")




## THIS FUNCTION IS CALLED by main()
## NEED TO MOVE THESE BLOCKS OUTSIDE OF the install_tomcat_on_instances as they are now called from main()
## NEW
#def wait_for_all_public_ips(ec2_client, instance_ids, timeout=60):
#    start_time = time.time()
#    while time.time() - start_time < timeout:
#        response = ec2_client.describe_instances(InstanceIds=instance_ids)
#        all_ips = []
#        for reservation in response['Reservations']:
#            for instance in reservation['Instances']:
#                ip = instance.get('PublicIpAddress')
#                if ip:
#                    all_ips.append({'InstanceId': instance['InstanceId'], 'PublicIpAddress': ip})
#        if len(all_ips) == len(instance_ids):
#            return all_ips
#        time.sleep(5)
#    raise TimeoutError("Not all instances received public IPs in time.")
#


# NEW1 This is an improvement on wait_for_all_public_ips with exponential backoff and also include private ips and 
# instance_ids in the array (list of dictionaries) instance_ips like with my original code.
def wait_for_all_public_ips(ec2_client, instance_ids, exclude_instance_id=None, timeout=120):
    """
    Waits for all EC2 instances (excluding the controller) to receive public IPs.
    Uses exponential backoff for retries and includes private IPs in the result.
    """
    start_time = time.time()
    attempt = 0
    delay = 5  # initial delay in seconds

    # Filter out the controller instance if provided
    filtered_instance_ids = [iid for iid in instance_ids if iid != exclude_instance_id]

    while time.time() - start_time < timeout:
        attempt += 1
        print(f"[DEBUG] Attempt {attempt}: Checking public IPs...")

        response = ec2_client.describe_instances(InstanceIds=filtered_instance_ids)
        instance_ips = []

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                public_ip = instance.get('PublicIpAddress')
                private_ip = instance.get('PrivateIpAddress')
                instance_id = instance['InstanceId']

                if public_ip:
                    instance_ips.append({
                        'InstanceId': instance_id,
                        'PublicIpAddress': public_ip,
                        'PrivateIpAddress': private_ip
                    })

        if len(instance_ips) == len(filtered_instance_ids):
            print(f"[INFO] All {len(instance_ips)} instances have public IPs.")
            return instance_ips

        print(f"[DEBUG] {len(instance_ips)} of {len(filtered_instance_ids)} instances have public IPs. Retrying in {delay} seconds...")
        time.sleep(delay)
        delay = min(delay * 2, 30)  # exponential backoff with a max delay of 30 seconds

    raise TimeoutError(f"Not all instances received public IPs within {timeout} seconds.")





# THIS FUNCTION IS CALLED BY main()
def install_tomcat_on_instances(instance_ips, security_group_ids):
# import instance_ips and security_group_ids from newly defined main() below
# move these imports to outside of the function as we will be adding more functions to this file (a main() wrapper around
# this function (see below)
#    import boto3
#    from dotenv import load_dotenv
#    import os
#    import paramiko
#    import time
#    from concurrent.futures import ThreadPoolExecutor, as_completed
#    import json
#    import sys


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




# Move the instance public_ip code out of the install_tomcat_on_instances and into main() below
# main() will be executed first and will ensure all instances are up and have public_ips
#
#    # Define the instance ID to exclude (the EC2 controller)
#    exclude_instance_id = 'i-0aaaa1aa8907a9b78'
#
#
#
#    # Debugging: Print the value of exclude_instance_id
#    print(f"exclude_instance_id: {exclude_instance_id}")
#
#
#
#
#    ## add this because getting a scope error in the multi-threaded setup with exclude_instance_id
#    ## if it prints out ok then it is not a scope or access issue.
#    ## Ensure exclude_instance_id is accessible within the threads
#    #def check_exclude_instance_id():
#    #    print(f"exclude_instance_id: {exclude_instance_id}")
#    #
#    #with ThreadPoolExecutor(max_workers=len(public_ips)) as executor:
#    #    futures = [executor.submit(check_exclude_instance_id) for _ in range(len(public_ips))]
#    #    for future in as_completed(futures):
#    #        future.result()
#    #
#

    # Establish a session with AWS
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )

    # Create an EC2 client
    my_ec2 = session.client('ec2')



## REMOVE this entire block. This block will be moved into the main() below to ensure all EC2 instances are up and 
## have public_ips

#    # for modular case need to insert new code below since no delay as with the manual wrapper case.  The new code is 
#    # below for modular case
#
#    # Function to wait for all instances to be in running state
#    def wait_for_all_instances_running(instance_ids, ec2_client):
#        while True:
#            response = ec2_client.describe_instance_status(InstanceIds=instance_ids)
#            all_running = all(
#                instance['InstanceState']['Name'] == 'running'
#                for instance in response['InstanceStatuses']
#            )
#            if all_running:
#                break
#            print("Waiting for all instances to be in running state...")
#            time.sleep(10)
#
#
#
#
#    # Describe the running instances
#    # for modular case need to add pending as well
#    #response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
#    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])
#
#
#
#
#
#
#    # Debugging: Print the value of exclude_instance_id
#    print(f"exclude_instance_id: {exclude_instance_id}")
#
#
#
#
#    # New code for modular case:
#    # Get the instance IDs of the running instances except the excluded instance ID
#    instance_ids = [
#        instance['InstanceId']
#        for reservation in response['Reservations']
#        for instance in reservation['Instances']
#        if instance['InstanceId'] != exclude_instance_id
#    ]
#
#
#    # New code for modular case:
#    # Wait for all instances to be in running state
#    wait_for_all_instances_running(instance_ids, my_ec2)
#
#
#    # New code for modular case:
#    # Add a delay to ensure public IPs are available before proceeding with the installation
#    # This is the latest addition to the code becasue still seeing the issue. 20 seconds was sufficient in manual wrapper
#    # code setup
#    print("Adding delay to ensure public IPs are available...")
#    time.sleep(20)
#
#
#    # Describe the running instances again to get updated information
#    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
#
#
#
#
#    # Get the public IP addresses and security group IDs of the running instances except the excluded instance ID
#    public_ips = []
#    private_ips = []
#    security_group_ids = []
#    instance_ids = []
#    for reservation in response['Reservations']:
#        for instance in reservation['Instances']:
#            if instance['InstanceId'] != exclude_instance_id:
#               
#                # for the revised code version for this module to support sequential module execution rather than the
#                # manual serial wrapper approach, comment out the next two lines and make them conditionals since the
#                # issue is with public ips being avaiable prior to installing tomcat.
#                #public_ips.append(instance['PublicIpAddress'])
#                #private_ips.append(instance['PrivateIpAddress'])
#                if 'PublicIpAddress' in instance:
#                    public_ips.append(instance['PublicIpAddress'])
#                if 'PrivateIpAddress' in instance:
#                    private_ips.append(instance['PrivateIpAddress'])
#
#
#     #           public_ips.append(instance['PublicIpAddress'])
#     #           private_ips.append(instance['PrivateIpAddress'])
#                instance_ids.append(instance['InstanceId'])
#                for sg in instance['SecurityGroups']:
#                    security_group_ids.append(sg['GroupId'])
#
#    # UPDATE: I can remove this code block below and put this in 5b_ script to modularize the python scripts
#    # properly for debugging. Sometimes don't want to run this 6_ script as it is very time consuming to install
#    # tomcat9 on all 50 target EC2 instances
#    # Save instance IDs and security group IDs to a file
#    # The instance_id and the security_group_ids will be needed in the AWS ALB script in a different .py file
#    #data = {
#    #    'instance_ids': instance_ids,
#    #    'security_group_ids': list(set(security_group_ids))
#    #}
#    #with open('instance_ids.json', 'w') as f:
#    #    json.dump(data, f)
#
#
#
#
#
#
#    #move this block for multi-threading so public_ips are present when this is run
#    # Ensure public_ips is not empty before creating ThreadPoolExecutor
#    if not public_ips:
#        print("No public IPs found. Exiting.")
#        sys.exit(1)
#
#    # Added code for moudle execution
#    # Debugging: Print instance details to verify public IPs are being retrieved correctly
#    # this is to debug the module execution of this script making sure public ips are present prior to tomcat execution in
#    # the ThreadPoolExecutor
#    for i, instance_id in enumerate(instance_ids):
#        print(f"Instance {i + 1}:")
#        print(f"  Instance ID: {instance_id}")
#        print(f"  Public IP Address: {public_ips[i] if i < len(public_ips) else 'N/A'}")
#        print(f"  Private IP Address: {private_ips[i] if i < len(private_ips) else 'N/A'}")
#




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


    # Add a security group rule to allow access to port 22
    for sg_id in set(security_group_ids):
        try:
            my_ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise





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


    # Add a security group rule to allow access to port 8080
    for sg_id in set(security_group_ids):
        try:
            my_ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 8080,
                        'ToPort': 8080,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise


## The instances should be up and running wiht public_ips by the time this code is run because main(), which is
## run first now has the code in it.
#    # Function to wait for instance to be in running state and pass status checks
#    def wait_for_instance_running(instance_id, ec2_client):
#        instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
#        while (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] != 'running' or
#               instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] != 'ok' or
#               instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] != 'ok'):
#            print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
#            time.sleep(10)
#            instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])


# Rewrite this code with AND logic. This will ensure all instances up and running prior to attempting to SSH
# with the ThreadPoolExecutor
# This will loop until all are running and ok.
    def wait_for_instance_running(instance_id, ec2_client):
        while True:
            instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
            if (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running' and
                instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and
                instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok'):
                break
            print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
            time.sleep(10)




# Function to install Tomcat on an instance
    def install_tomcat(ip, private_ip, instance_id):
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
            return ip, private_ip, False

        print(f"Connected to {ip}. Executing commands...")
        for command in commands:
            for attempt in range(3):
                stdin, stdout, stderr = ssh.exec_command(command)
                stdout_output = stdout.read().decode()
                stderr_output = stderr.read().decode()
                print(f"Executing command: {command}")
                print(f"STDOUT: {stdout_output}")
                print(f"STDERR: {stderr_output}")
                
                # Check for real errors and ignore warnings
                if "E: Package 'tomcat9' has no installation candidate" in stderr_output:
                    print(f"Installation failed for {ip} due to package issue.")
                    stdin.close()
                    stdout.close()
                    stderr.close()
                    ssh.close()
                    return ip, private_ip, False
                
                # Ignore specific warnings that are not critical errors
                if "WARNING:" in stderr_output:
                    print(f"Warning on {ip}: {stderr_output}")
                    stderr_output = ""
                
                if stderr_output.strip():  # If there are any other errors left after ignoring warnings
                    print(f"Error executing command on {ip}: {stderr_output}")
                    stdin.close()
                    stdout.close()
                    stderr.close()
                    ssh.close()
                    return ip, private_ip, False
                
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
        return ip, private_ip, True

    # MOVED THIS BLOCK TO ABOVE
    ### added this because when running this as a module getting an error that there are no public ips on the instances
    ## I did check and the instances did have public ips.
    ## Ensure public_ips is not empty before creating ThreadPoolExecutor
    #if not public_ips:
    #    print("No public IPs found. Exiting.")
    #    sys.exit(1)
    #










    # Use ThreadPoolExecutor to run installations in parallel
    # In this updated script, the `install_tomcat` function returns a tuple containing the IP address and the result (`True` for success, `False` for failure). The script collects the IP addresses of both successful and failed installations in separate lists (`successful_ips` and `failed_ips`) and prints them out at the end. This way, you can easily identify which instances had successful installations and which ones failed.
    # Also: This script now correctly checks for both SSH connection failures and package installation failures, and prints out the IP addresses of both successful and failed installations.
    # This is to troubleshoot an issue where with 50 instances there were 2 that did not have Installation completed.

    failed_ips = []
    successful_ips = []
    failed_private_ips = []
    successful_private_ips = []

   # HERE IS THE MAIN CHANGE FOR THE multiprocessing optmization. First we are going to tie the thread pools
   # to the number of cores (the VPS has 6 CPU cores).  Each ThreadPoolExecutor will have max workers of 6 at a time.
   # Previously we had max_workers set to length of public_ips which is 50. This is creating a lot of contention with only
   # 6 cores and a lot of context switching.    To optimize this first we will restrict this to the os.cpu_count of 6
   # This means that there will be 6 threads at the same time. To further optimize this with main() function below, we 
   # will also start 6 processes defined by num_processes=os.cpu.count (6 as well.  Each process wil invoke the 
   # install_tomcat_on_instances function running the 6 ThreadPoolExecutor threads on its dedicated core.   Thus there
   # are on average 6 threads running on a process on each of the 6 cores, for 36 concurrent SSH tomcat installations
   # at any time. This will reduce the contention of just running ThreadPoolExecutor with all 50 threads randomly assigned
   # across the cores which created a lot of context switching. NOTE that chunk size is another variable. See main() below
   # Chunk size is the chunk of ips that are grabbed by each process. So if 50 ip addresses each of the 6 processes will
   # get 8 ip addresses, and each process can use the 6 threads in the process to process the SSH connections.  In this
   # case 6 ips processed immediately and then the other 2 when some of the 6 threads are done with the initial 6 ips.
   # however need additionl logic because with 50 instances and 6 processes there are 2 "orphaned" ips that need to be
   # dealt with. This requires additional logic.




    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]


# with max_workders = 6
#    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
#        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]


# with max_workers=50
   #with ThreadPoolExecutor(max_workers=len(public_ips)) as executor:
        #futures = [executor.submit(install_tomcat, ip, private_ip, instance_id) for ip, private_ip, instance_id in zip(public_ips, private_ips, instance_ids)]
        for future in as_completed(futures):
            ip, private_ip, result = future.result()
            if result:
                successful_ips.append(ip)
                successful_private_ips.append(private_ip)
            else:
                failed_ips.append(ip)
                failed_private_ips.append(private_ip)

    if successful_ips:
        print(f"Installation succeeded on the following IPs: {', '.join(successful_ips)}")
        print(f"Installation succeeded on the following private IPs: {', '.join(successful_private_ips)}")
    if failed_ips:
        print(f"Installation failed on the following IPs: {', '.join(failed_ips)}")
        print(f"Installation failed on the following private IPs: {', '.join(failed_private_ips)}")

    print("ThreadPoolExecutor script execution completed.")


# COMMENT this out. The call from the master script will have to run main() instead. Main() will then call the 
# install_tomcat_on_instances function above.   Main() is below and is used to establish the multiprocessing aspect
# of the multi-threading in install_tomcat_on_instances above.
#if __name__ == "__main__":
#    install_tomcat_on_instances()











# MAIN function is the second change to integrate multi-processing with the multi-threading in the install_tomcat_on_instances 
# function above. Move a lot of the public ip verification code into this block as well out of the install_tomcat_on_instances
# function. When the master script invokes this module main is run first and will verify all the public_ips are up
# and then main() calls the install_tomcat_on_instances function in the domain of each of its 6 processes that it creates


def main():
    load_dotenv()

    # Set variables from environment
    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("region_name")

    # Establish a session with AWS
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )

    # Create an EC2 client
    my_ec2 = session.client('ec2')

    # Define the instance ID to exclude (the EC2 controller)
    exclude_instance_id = 'i-0aaaa1aa8907a9b78'
    # Debugging: Print the value of exclude_instance_id
    print(f"exclude_instance_id: {exclude_instance_id}")


    # Describe the running instances (including pending)
    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending']}])

    # Get the instance IDs of the running instances except the excluded instance ID
    instance_ids = [
        instance['InstanceId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        if instance['InstanceId'] != exclude_instance_id
    ]



    # Wait for all instances to be in running state
    while True:
        response_statuses = my_ec2.describe_instance_status(InstanceIds=instance_ids)
        all_running = all(
            instance['InstanceState']['Name'] == 'running'
            for instance in response_statuses['InstanceStatuses']
        )
        if all_running:
            break
        print("Waiting for all instances to be in running state...")
        time.sleep(10)





###  NEW1: REMOVE the 3 blocks below. Replace these with the new improved function call below for 
##   wait_for_all_public_ips
#    # NEW
#    # Add a delay to ensure public IPs are available before proceeding with the installation
#    print("Adding delay to ensure public IPs are available...")
#    time.sleep(40)
#
#
#    # Describe the running instances again to get updated information
#    response = my_ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
#
#    # Get the public IP addresses and security group IDs of the running instances except the excluded instance ID
#    instance_ips = [
#        {
#            'InstanceId': instance['InstanceId'],
#            'PublicIpAddress': instance.get('PublicIpAddress'),
#            'PrivateIpAddress': instance.get('PrivateIpAddress')
#        }
#        for reservation in response['Reservations']
#        for instance in reservation['Instances']
#        if instance['InstanceId'] != exclude_instance_id
#    ]
#






##   NEW for main(): Replace the blocks above with this new code with the improved function call below
#    wait_for_all_public_ips 
#    # Now wait until all instances have public IPs

#    try:
#        instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, timeout=60)
#    except TimeoutError as e:
#        print(f"[ERROR] {e}")
#        return  # or handle the error appropriately
#
#    Note have added exclue_instance_id in definition of instance_ips from original code because we do not want to
#    install tomcat on the controller!!!
#
    try:
        instance_ips = wait_for_all_public_ips(my_ec2, instance_ids, exclude_instance_id=exclude_instance_id, timeout=120)
    except TimeoutError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)





## DEBUGS for public ips

    # add this debug as well for the model2 scope issue?????
    print("[DEBUG] instance_ips initialized with", len(instance_ips), "entries")

    # NEW
    # After instance_ips is populated
    null_ips = [ip for ip in instance_ips if 'PublicIpAddress' not in ip or not ip['PublicIpAddress']]
    print(f"[DEBUG] Null or missing IPs: {null_ips}")

    # NEW
    expected_count = len(instance_ids)
    actual_count = len(instance_ips)
    if actual_count != expected_count:
        print(f"[WARNING] Expected {expected_count} IPs but got {actual_count}")

    # Ensure public_ips is not empty before proceeding
    if not any(ip['PublicIpAddress'] for ip in instance_ips):
        print("No public IPs found. Exiting.")
        sys.exit(1)


    security_group_ids = [
        sg['GroupId']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        for sg in instance['SecurityGroups']
        if instance['InstanceId'] != exclude_instance_id
    ]



##  Now that public_ips are all present, engage the multiprocessing on the instances with the 3 variant models
#   below for install_tomcat_on_instances main function. This function will use the ThreadPoolExecutor to 
#   install tomcat on the instances as detailed below and above. Main varaibles are num_processes and chunk_size
#   and max_workers (threads per process)




    # Use multi-processing to distribute SSH connections across multiple cores

    # with num_proceses = 6
    #num_processes = os.cpu_count()
    
    # with num_procsses = 8
    num_processes = 8

    # the chunk_size is determined by number of instances divided by num_processes. num_processes is 6 and 
    # number of instances is 50 so 50/6 = 8. The division is // for an integer with floor division
    # this chunk size is then used to calculate the block of ips to pass to install_tomcat_on_instances (see below)
    # for each process iteration i= 0 to num_processes-1 or 0 to 5 for processes 1 through 6
    # Each process is assigned a block of 8 with the last 2 leftovers assigned to the last chunk which is assigned 
    # to the last process #6. So the last process will get 10 ips to process. 
    # As noted above the processes utlize install_tomcat_on_instances which runs ThreadPoolExecutor of 6 threads to
    # process the assigned ip block.  So 6 ips handled immediately and the other 2 when any other thread frees up
    # This minimizes contention and context switching.
    

### CHOOSE ONE MODEL BELOW:


### MODEL 1:
## chunk_size determined by num_processes and number of IPs (deterministic)
## the remainder ips are processed by the last process and all the num_processes are used
#
#    chunk_size = len(instance_ips) // num_processes
#    processes = []
#
#    ## Debugging instance_ips
#    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
#    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')
#
#
#
#    for i in range(num_processes):
#        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
#        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
#        if i == num_processes - 1:  # Add remaining instances to the last chunk
#            chunk += instance_ips[(i + 1) * chunk_size:]
#        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
#        processes.append(process)
#        process.start()
#
#    for process in processes:
#        process.join()
#
#





### MODEL 2 REMAINDER METHOD: (Don't use this. Use the revised version below)
### Decouple chunk_size from num_processes and make sure remaining ips still get processed
### the number of actual processes created is dynamic. For example with 50 IPs and chunk_size of 12, there will
### be 4 processes created even though num_processes is 8.
### NOTE only the required number of num_processes will be created (for production and optimized)
#
#    chunk_size = 12
#    processes = []
#
#
#    # adding debugs for instande_ips scope issue???
#    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
#    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')
#
#
#
#    # Calculate how many full chunks we actually need
#    num_chunks = len(instance_ips) // chunk_size
#    remainder = len(instance_ips) % chunk_size
#
#    for i in range(num_chunks):
#        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
#        
#        # If this is the last used chunk, add the remaining IPs
#        if i == num_chunks - 1 and remainder > 0:
#            chunk += instance_ips[(i + 1) * chunk_size:]
#
#        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
#        processes.append(process)
#        process.start()
#
#    for process in processes:
#        process.join()
#
#


## REVISED MODEL2: Using ceiling division and create an additional process to deal with leftover rather than adding
## it to the last process suing remainder method as above
##  This code is cleaner and also we don't need to deal with remainders

    chunk_size = 12
    processes = []

    # Debugging instance_ips
    print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
    print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')

    # Calculate how many chunks we need (ceiling division)
    num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size

    for i in range(num_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, len(instance_ips))  # safely cap the end index
        chunk = instance_ips[start:end]

        # Diagnostic logging
        print(f"[DEBUG] Process {i}: chunk size = {len(chunk)}")
        print(f"[DEBUG] Process {i}: IPs = {[ip['PublicIpAddress'] for ip in chunk]}")

        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()






### MODEL 3: REMAINDER model. Do not use this.  Decouple chunk_size from num_processes and make sure remaining ips get processed but spawn
### all num_processes for testing purposes
#
#
#    chunk_size = 12
#    processes = []
#
#    # Calculate how many full chunks we need
#    num_chunks = len(instance_ips) // chunk_size
#    remainder = len(instance_ips) % chunk_size
#
#
#    for i in range(num_processes):
#        if i < num_chunks:
#            chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
#            if i == num_chunks - 1 and remainder > 0:
#                chunk += instance_ips[(i + 1) * chunk_size:]
#            process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
#        else:
#            # Dummy process that just logs it's unused
#            process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
#        
#        processes.append(process)
#        process.start()
#
#    for process in processes:
#        process.join()#
#



### REVISED MODEL3: Using ceiling devision. This model 3 will create num_processes and whatever is unused will just run
### unused. This is just for testing purposes.
#
#    chunk_size = 12
#    processes = []
#
#    # Calculate how many chunks we need (ceiling division)
#    num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size
#
#    for i in range(num_processes):
#        if i < num_chunks:
#            start = i * chunk_size
#            end = min(start + chunk_size, len(instance_ips))
#            chunk = instance_ips[start:end]
#            process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
#        else:
#            # Dummy process that just logs it's unused
#            process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
#
#        processes.append(process)
#        process.start()
#
#    for process in processes:
#        process.join()
#


# We need to run main first when this is invoked from the master script. Then main will call the install_tomcat_on_instances to invoke the ThreadPoolExecutor for each process started in main.
if __name__ == "__main__":
    main()
