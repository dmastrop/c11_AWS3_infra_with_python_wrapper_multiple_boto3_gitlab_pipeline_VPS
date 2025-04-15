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

# Initialize the Elastic Beanstalk client using the session
eb_client = session.client('elasticbeanstalk')

# Create a new Elastic Beanstalk environment with the existing Application Load Balancer
response = eb_client.create_environment(
    ApplicationName='your-application-name',
    EnvironmentName='your-environment-name',
    SolutionStackName='64bit Amazon Linux 2 v3.3.6 running Python 3.8',
    OptionSettings=[
        {
            'Namespace': 'aws:elasticbeanstalk:environment',
            'OptionName': 'LoadBalancerType',
            'Value': 'application'
        },
        {
            'Namespace': 'aws:elasticbeanstalk:environment:loadbalancer',
            'OptionName': 'LoadBalancerName',
            'Value': 'your-existing-load-balancer-name'
        }
    ]
)

# Verify the environment creation
print(response)

