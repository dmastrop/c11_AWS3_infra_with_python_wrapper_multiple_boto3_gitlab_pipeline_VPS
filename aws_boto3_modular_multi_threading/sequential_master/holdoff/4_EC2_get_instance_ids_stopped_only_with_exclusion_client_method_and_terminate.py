import boto3
from dotenv import load_dotenv
import os

# This will load env vars from the .env file
# They will be available to use in the rest of the code blocks below
load_dotenv()

# Set variables
# os.getenv will load from the .env. The .env will be created on the fly by the gitlab pipeline script
aws_access_key = f'{os.getenv("AWS_ACCESS_KEY_ID")}'
aws_secret_key = f'{os.getenv("AWS_SECRET_ACCESS_KEY")}'
region_name = f'{os.getenv("region_name")}'

def get_stopped_instance_ids(exclude_ids=None):
    if exclude_ids is None:
        exclude_ids = []

    # Create a custom session
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )

    # Create an EC2 client with the custom session
    ec2_client = session.client('ec2')

    try:
        # Describe instances with filters to get only stopped instances
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['stopped']
                }
            ]
        )
        
        # Extract instance IDs
        instance_ids = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                if instance_id not in exclude_ids:
                    instance_ids.append(instance_id)
        
        return instance_ids
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def terminate_ec2_instances(instance_ids):
    # Create a custom session
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )

    # Create an EC2 client with the custom session
    ec2_client = session.client('ec2')

    try:
        # Terminate the instances
        response = ec2_client.terminate_instances(InstanceIds=instance_ids)
        print("Terminating instances:", instance_ids)
        print(response)
    except Exception as e:
        print(f"An error occurred: {e}")




if __name__ == "__main__":
    # Replace with your instance IDs to exclude
    exclude_ids = ['i-07139100f9fe32799', 'i-0ddbf7fda9773252b', 'i-0732df334cf72a173', 'i-0dcf3c32c9eb27580', 'i-06cfd334e2185f50a', 'i-02f502ffed943323b', 'i-09505844789cb6cc1', 'i-0c4cbe350c527ed22', 'i-08f19bbd0851ebcef', 'i-0837fb5a39ae707bf', 'i-007c8b4456e3c47c5', 'i-02b5d0832038f38f1', 'i-06b36bf3f3978a08f', 'i-0cb768b664e018ba6', 'i-09b7c12f4b164a1cb', 'i-0a9449b813fbe0ebe', 'i-07132a3adb01dde68']

    # Get stopped instance IDs excluding the specified IDs
    stopped_instance_ids = get_stopped_instance_ids(exclude_ids)
    print("Stopped Instance IDs (excluding specified IDs):", stopped_instance_ids)

    # Terminate the stopped instances that are not in the exclusion list
    if stopped_instance_ids:
        terminate_ec2_instances(stopped_instance_ids)
    else:
        print("No instances to terminate.")

