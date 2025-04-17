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
# Check for existing elastic beanstalk apps


# Check for existing elastic beanstalk apps
existing_apps = eb_client.describe_applications()
for app in existing_apps['Applications']:
    print(f"ApplicationName: {app['ApplicationName']}")
    print(app['ApplicationName'])



# Create the Elastic Beanstalk application
application_name = 'tomcatapplication'
#eb_client.create_application(
#    ApplicationName=application_name,
#    Description='Description of your application'
#)


#add error handling for Create the Elastic Beanstalk application:
try:
    eb_client.create_application(
    ApplicationName=application_name,
    Description='Description of your application'
)
except botocore.exceptions.ClientError as error:
    print(f"An error occurred: {error}")





# Create a new Elastic Beanstalk environment with the existing Application Load Balancer
# SolutionStackName https://docs.aws.amazon.com/elasticbeanstalk/latest/platforms/platforms-supported.html#platforms-supported.python

response = eb_client.create_environment(
    ApplicationName=application_name,
    EnvironmentName='tomcatenvironment',
    #SolutionStackName='64bit Amazon Linux 2 v3.3.14 running Python 3.8',  # Updated solution stack name
    SolutionStackName='64bit Amazon Linux 2 v4.8.0 running Tomcat 9 Corretto 8',
    OptionSettings=[
        {
            'Namespace': 'aws:elasticbeanstalk:environment',
            'OptionName': 'LoadBalancerType',
            'Value': 'application'
        },

        {
            'Namespace': 'aws:elasticbeanstalk:environment:process',
            'OptionName': 'LoadBalancerName',
            'Value': 'tomcat-load-balancer'
        }


    ]
)

# Make sure to use tomcat-load-balancer which is already created

# Verify the environment creation
print(response)

