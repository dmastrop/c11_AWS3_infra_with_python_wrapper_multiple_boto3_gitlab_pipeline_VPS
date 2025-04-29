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
image_id = f'{os.getenv("image_id")}'
instance_type = f'{os.getenv("instance_type")}'
key_name = f'{os.getenv("key_name")}'
min_count = f'{os.getenv("min_count")}'
max_count = f'{os.getenv("max_count")}'


def start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count):
    # Establish a session with AWS
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    
    # Create an EC2 client
    my_ec2 = session.client('ec2')
    
    # Start EC2 instances
    response = my_ec2.run_instances(
        ImageId=image_id,
        InstanceType=instance_type,
        KeyName=key_name,
        MinCount=int(min_count),
        MaxCount=int(max_count)
    )
    
    return response


response = start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count)
print(response)

