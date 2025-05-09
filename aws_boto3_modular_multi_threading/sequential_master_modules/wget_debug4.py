def wget_debug():
    import boto3
    from dotenv import load_dotenv
    import os
    import paramiko
    import time
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
        sys.stdout.flush()
    except Exception as e:
        print(f"Error launching EC2 instance: {e}")
        sys.stdout.flush()
        exit(1)

    # Function to wait for instance to be in running state and pass status checks
    def wait_for_instance_running(instance_id, ec2_client):
        while True:
            try:
                instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id])
                print(f"Instance status: {instance_status}")
                sys.stdout.flush()
                if (instance_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running' and
                    instance_status['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and
                    instance_status['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok'):
                    print(f"Instance {instance_id} is now running and has passed status checks.")
                    sys.stdout.flush()
                    break
                else:
                    print(f"Waiting for instance {instance_id} to be in running state and pass status checks...")
                    sys.stdout.flush()
                    time.sleep(10)
            except Exception as e:
                print(f"Error checking instance status: {e}")
                sys.stdout.flush()
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
            sys.stdout.flush()
        else:
            print(f"Instance DNS: {instance_dns}")
            sys.stdout.flush()
    except Exception as e:
        print(f"Error retrieving instance details: {e}")
        sys.stdout.flush()
        exit(1)

    # Function to install wget and run the stress test script on the instance
    def install_wget_and_run_script(instance_address, key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for attempt in range(5):
            try:
                print(f"Attempting to connect to {instance_address} (Attempt {attempt + 1})")
                sys.stdout.flush()
                ssh.connect(instance_address, port=22, username='ubuntu', key_filename=key_path)
                break
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                print(f"Connection failed: {e}")
                sys.stdout.flush()
                time.sleep(10)
        else:
            print(f"Failed to connect to {instance_address} after multiple attempts")
            sys.stdout.flush()
            return False

        print(f"Connected to {instance_address}. Executing commands...")
        sys.stdout.flush()

        commands = [
            "sudo DEBIAN_FRONTEND=noninteractive apt update",    
            #"sudo apt update",
            

            "sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install wget -y",
            #"sudo DEBIAN_FRONTEND=noninteractive apt install wget -y",
            #"sudo apt install wget -y",
            
            "echo 'while true; do wget -q -O- https://loadbalancer1.holinessinloveofchrist.com; done' > stress_test.sh",
            
            "chmod +x stress_test.sh",
            
            # Move this out of the command block so that the wget shell script output does NOT print to gitlab console.
            # Otherwise, the buffer overflows and the print statements for many of the scripts stop going to the console.
            # "./stress_test.sh"
        ]
        
        for command in commands:
            print(f"Executing command: {command}")
            sys.stdout.flush()
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout_output = stdout.read().decode()
            stderr_output = stderr.read().decode()
        
            # Check if wget is already installed and proceed if it is
            # This issue caused the script to abort without running the shell script
            if "wget is already the newest version" in stdout_output or "wget is already installed" in stdout_output:
                print("wget is already installed. Proceeding with the stress test script.")
                sys.stdout.flush()
                continue



            print(f"STDOUT: {stdout_output}")
            sys.stdout.flush()
            print(f"STDERR: {stderr_output}")
            sys.stdout.flush()
            
            if stderr_output.strip() and "WARNING: apt does not have a stable CLI interface." not in stderr_output:
                print(f"Error executing command on {instance_address}: {stderr_output}")
                sys.stdout.flush()
            #if stderr_output.strip():
                #print(f"Error executing command on {instance_address}: {stderr_output}")
                stdin.close()
                stdout.close()
                stderr.close()
                ssh.close()
                return False
            
            time.sleep(10)
        

        # Execute the stress test script without printing its output
        # This was moved out of the command block above to prevent it printing to the console with the other stuff.
        ssh.exec_command("./stress_test.sh")



        stdin.close()
        stdout.close()
        stderr.close()
        #ssh.close()

        transport = ssh.get_transport()
        if transport is not None:
            transport.close()
        
        print(f"Installation completed on {instance_address}")
        sys.stdout.flush()
        print(f"Instance ID {instance_id} is sending wget traffic.")
        sys.stdout.flush()
        return True

    # Path to your SSH key file (replace with your actual key file path)
    key_file_path = 'EC2_generic_key.pem'

    # Install wget and run the stress test script on the instance
    install_wget_and_run_script(instance_dns if instance_dns else instance_ip, key_file_path)

    print(f"EC2 instance {instance_id} is created and stress traffic script is running.")
    sys.stdout.flush()


    # test2



if __name__ == "__main__":
    wget_debug()

