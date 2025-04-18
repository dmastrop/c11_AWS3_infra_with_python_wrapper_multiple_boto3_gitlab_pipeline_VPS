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
hosted_zone_id = 'Z055765416LPH0LA4ZBVA'  # Your Route 53 hosted zone ID
hosted_zone_name = 'elasticloadbalancer.holinessinloveofchrist.com'

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

# Use the native elastic beanstalk loadbalancer and build that up instead of tyring to add existing loadbalancer to the setup.

#'Namespace': 'aws:elasticbeanstalk:environment:loadbalancer',
#'OptionName': 'LoadBalancerName',
#'Value': 'tomcat-load-balancer'

        {
            'Namespace': 'aws:autoscaling:launchconfiguration',
            'OptionName': 'IamInstanceProfile',
            'Value': instance_profile_name
        },

# scale up the backend tomcat servers to 20
        {
            'Namespace': 'aws:autoscaling:asg',
            'OptionName': 'MinSize',
            'Value': '20'
        },


        {
            'Namespace': 'aws:autoscaling:asg',
            'OptionName': 'MaxSize',
            'Value': '20'
        },

       

    ]
)





# Verify the environment creation and save the beanstalk URL to a JSON file
# The CNAME (URL) will be saved into the file beanstalk_environment.json which will be used in the 
# beanstalk_wget script so that wget instance can send traffic to the beanstalk environment URL. This
# wget script is a different script file
# This script includes a loop to wait until the environment status is 'Ready' before attempting to retrieve the CNAME. Additionally, it uses the `get` method to safely access the 'CNAME' key, providing a default value of `None` if the key is not found.


# Wait for the environment to be ready and retrieve its description
while True:
    environments = eb_client.describe_environments(EnvironmentNames=['tomcat-environment'])
    environment_status = environments['Environments'][0]['Status']

    if environment_status == 'Ready':
        break

    print(f"Waiting for environment to be ready... Current status: {environment_status}")
    time.sleep(10)

# Verify the environment creation and save the beanstalk URL to a JSON file. Note using the get method to get
# the CNAME
environment_description = eb_client.describe_environments(EnvironmentNames=['tomcat-environment'])
beanstalk_url = environment_description['Environments'][0].get('CNAME', None)

if beanstalk_url is None:
    raise KeyError("CNAME not found in environment description")

print(f"Elastic Beanstalk URL: http://{beanstalk_url}")

beanstalk_data = {'CNAME': beanstalk_url}
with open('beanstalk_environment.json', 'w') as f:
    json.dump(beanstalk_data, f)

print(response)






## The next blocks of code are for creating an ACM SSL cert and getting it into issued state
## Then once the cert is ready adding the HTTPS listener to the existing beanstalk environment using
## the certificate arn of the aformentioned cert. This has to be for elasticloadbalancer.holinessinloveofchrist
## Route 53 hosted zone 

# Initialize the ELB client using the session
elb_client = session.client('elbv2')

# Retrieve the load balancer ARN and DNS name
load_balancers = elb_client.describe_load_balancers()
load_balancer_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
load_balancer_dns_name = load_balancers['LoadBalancers'][0]['DNSName']

print(f"Load Balancer DNS Name: {load_balancer_dns_name}")
sys.stdout.flush()

# Initialize the Route 53 client using the session
route53_client = session.client('route53')

# Add A record for the ALB DNS name to Route53 hosted zone as a routed A record
route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={
        'Changes': [
            {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': hosted_zone_name,
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': 'Z35SXDOTRQ7X7K',  # Hosted zone ID for the load balancer
                        'DNSName': load_balancer_dns_name,
                        'EvaluateTargetHealth': False
                    }
                }
            }
        ]
    }
)

print("A record added to Route 53")
sys.stdout.flush()

# Initialize the ACM client using the session
acm_client = session.client('acm')

# Request a new certificate using the custom DNS domain name
response = acm_client.request_certificate(
    DomainName=hosted_zone_name,
    ValidationMethod='DNS'
)

certificate_arn = response['CertificateArn']
print("Certificate ARN:", certificate_arn)
sys.stdout.flush()

# Wait for the certificate to be issued and retrieve the CNAME records for DNS validation
print("Waiting for certificate to be issued...")
time.sleep(60)  # Wait for 60 seconds

certificate_details = acm_client.describe_certificate(CertificateArn=certificate_arn)
domain_validation_options = certificate_details['Certificate']['DomainValidationOptions']

# Print the CNAME records
for option in domain_validation_options:
    if 'ResourceRecord' in option:
        cname_record = option['ResourceRecord']
        print(f"CNAME record: {cname_record['Name']} -> {cname_record['Value']}")
        sys.stdout.flush()

# Add CNAME records to Route 53
changes = []
for option in domain_validation_options:
    if 'ResourceRecord' in option:
        cname_record = option['ResourceRecord']
        changes.append({
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': cname_record['Name'],
                'Type': cname_record['Type'],
                'TTL': 300,
                'ResourceRecords': [{'Value': cname_record['Value']}]
            }
        })

route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={'Changes': changes}
)

print("CNAME records added to Route 53")
sys.stdout.flush()

# Wait for the certificate to be issued
while True:
    certificate_details = acm_client.describe_certificate(CertificateArn=certificate_arn)
    status = certificate_details['Certificate']['Status']
    if status == 'ISSUED':
        break
    print("Waiting for certificate to be issued...")
    sys.stdout.flush()
    time.sleep(30)

print("Certificate issued")
sys.stdout.flush()








# Add HTTPS listener to the existing Elastic Beanstalk environment
response = eb_client.update_environment(
    ApplicationName=application_name,
    EnvironmentName='tomcat-environment',
    OptionSettings=[
        {
            'Namespace': 'aws:elbv2:listener',
            'OptionName': 'ListenerEnabled',
            'Value': 'true'
        },
        {
            'Namespace': 'aws:elbv2:listener',
            'OptionName': 'SSLCertificateId',
            'Value': certificate_arn
        },
        {
            'Namespace': 'aws:elbv2:listener',
            'OptionName': 'Protocol',
            'Value': 'HTTPS'
        },
        {
            'Namespace': 'aws:elbv2:listener',
            'OptionName': 'Port',
            'Value': '443'
        }
    ]
)


print("HTTPS listener added to the Elastic Beanstalk environment")
sys.stdout.flush()

