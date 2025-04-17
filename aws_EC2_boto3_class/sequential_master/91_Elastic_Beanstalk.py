import boto3
from dotenv import load_dotenv
import os
import paramiko
import time
import sys
import json
from botocore.exceptions import ClientError



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


# Initialize the IAM client
iam_client = session.client('iam')



# Create an IAM role if it doesn't already exist
# assume_role_policy_document is the trust policy for the role not the permissions policies attached to it.
# that will come later (see below)
role_name = 'tomcat-role'
assume_role_policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

try:
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
    )
    print(f"Role {role_name} created successfully.")
except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
        print(f"Role {role_name} already exists. Skipping creation.")
    else:
        print(f"Error creating role: {e}")







# Attach policies to the role unless they are already attached to the role
policies = [
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier',
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier'
]

for policy_arn in policies:
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        print(f"Policy {policy_arn} attached to role {role_name}.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"Policy {policy_arn} already attached to role {role_name}. Skipping attachment.")
        else:
            print(f"Error attaching policy {policy_arn}: {e}")






# Create an instance profile if it doesn't already exist
instance_profile_name = 'tomcat-instance-profile'
try:
    iam_client.create_instance_profile(
        InstanceProfileName=instance_profile_name
    )
    print(f"Instance profile {instance_profile_name} created successfully.")
except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
        print(f"Instance profile {instance_profile_name} already exists. Skipping creation.")
    else:
        print(f"Error creating instance profile: {e}")




# Add the role to the instance profile if it isn't already added
try:
    iam_client.add_role_to_instance_profile(
        InstanceProfileName=instance_profile_name,
        RoleName=role_name
    )
    print(f"Role {role_name} added to instance profile {instance_profile_name}.")
except ClientError as e:
    if e.response['Error']['Code'] == 'LimitExceeded':
        print(f"Role {role_name} already added to instance profile {instance_profile_name}. Skipping addition.")
    else:
        print(f"Error adding role to instance profile: {e}")




# Initialize the Elastic Beanstalk client using the session
eb_client = session.client('elasticbeanstalk')
# Check for existing elastic beanstalk apps


# Check for existing elastic beanstalk apps
existing_apps = eb_client.describe_applications()
for app in existing_apps['Applications']:
    print(f"ApplicationName: {app['ApplicationName']}")
    print(app['ApplicationName'])






# Create the Elastic Beanstalk application
application_name = 'tomcat-application'
try:
    eb_client.create_application(
        ApplicationName=application_name,
        Description='Description of your application'
    )
    print(f"Application {application_name} created successfully.")
except ClientError as e:
    if e.response['Error']['Code'] == 'InvalidParameterValue':
        print(f"Application {application_name} already exists. Skipping creation.")
    else:
        print(f"Error creating application: {e}")




# Create a new Elastic Beanstalk environment with the existing Application Load Balancer
# SolutionStackName https://docs.aws.amazon.com/elasticbeanstalk/latest/platforms/platforms-supported.html#platforms-supported.python
# Make sure to use tomcat-load-balancer which is already created


# Create a new Elastic Beanstalk environment with the instance profile
response = eb_client.create_environment(
    ApplicationName=application_name,
    EnvironmentName='tomcat-environment',
    SolutionStackName='64bit Amazon Linux 2 v4.8.0 running Tomcat 9 Corretto 8',
    OptionSettings=[
        {
            'Namespace': 'aws:elasticbeanstalk:environment',
            'OptionName': 'LoadBalancerType',
            'Value': 'application'
        },

        #{
        #    'Namespace': 'aws:elasticbeanstalk:environment:process',
        #    'OptionName': 'LoadBalancerName',
        #    'Value': 'tomcat-load-balancer'
        #},


# Use the native elastic beanstalk loadbalancer and build that up instead of tyring to add existing loadbalancer to the setup.
        #{
        #    'Namespace': 'aws:elasticbeanstalk:environment:loadbalancer',
        #    'OptionName': 'LoadBalancerName',
        #    'Value': 'tomcat-load-balancer'
        #},

       
        {
            'Namespace': 'aws:autoscaling:launchconfiguration',
            'OptionName': 'IamInstanceProfile',
            'Value': instance_profile_name
        }
    ]
)







# Verify the environment creation
print(response)

