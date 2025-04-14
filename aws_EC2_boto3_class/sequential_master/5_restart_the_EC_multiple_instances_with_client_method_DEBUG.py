import boto3
from dotenv import load_dotenv
import os
import sys

# This will load env vars from the .env file
# They will be available to use in the rest of the code blocks below
load_dotenv()

# Set variables
# os.getenv will load from the .env. The .env will be created on the fly by the gitlab pipeline script
aws_access_key = f'{os.getenv("AWS_ACCESS_KEY_ID")}'
aws_secret_key = f'{os.getenv("AWS_SECRET_ACCESS_KEY")}'
region_name = f'{os.getenv("region_name")}'
image_id = f'{os.getenv("image_id")}'
instance_type = f'{os.getenv("instance_type")}'
key_name = f'{os.getenv("key_name")}'
min_count = f'{os.getenv("min_count")}'
max_count = f'{os.getenv("max_count")}'

# Debugging: Print the loaded environment variables
print("AWS Access Key:", aws_access_key)
print("AWS Secret Key:", aws_secret_key)
print("Region Name:", region_name)
print("Image ID:", image_id)
print("Instance Type:", instance_type)
print("Key Name:", key_name)
print("Min Count:", min_count)
print("Max Count:", max_count)

def start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count):
    # Establish a session with AWS
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region_name
        )
        print("AWS session established.")
    except Exception as e:
        print("Error establishing AWS session:", e)
        sys.exit(1)
    
    # Create an EC2 client
    try:
        my_ec2 = session.client('ec2')
        print("EC2 client created.")
    except Exception as e:
        print("Error creating EC2 client:", e)
        sys.exit(1)
    
    # Start EC2 instances
    try:
        response = my_ec2.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=int(min_count),
            MaxCount=int(max_count)
        )
        print("EC2 instances started:", response)
    except Exception as e:
        print("Error starting EC2 instances:", e)
        sys.exit(1)
    
    return response

response = start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count)
#print(response)


# Print the response in a more readable format using json.dumps for pretty printing
print(json.dumps(response, indent=4))



# Print the response in a more readable format
if 'Instances' in response:
    for i, instance in enumerate(response['Instances']):
        print(f"Instance {i+1}:")
        print(f"  Instance ID: {instance['InstanceId']}")
        print(f"  Instance Type: {instance['InstanceType']}")
        print(f"  Image ID: {instance['ImageId']}")
        print(f"  State: {instance['State']['Name']}")
        print(f"  Private IP Address: {instance['PrivateIpAddress']}")
        print(f"  Subnet ID: {instance['SubnetId']}")
else:
    print("No instances found in the response.")



