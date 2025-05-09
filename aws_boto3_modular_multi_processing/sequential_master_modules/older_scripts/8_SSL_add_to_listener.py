import boto3
import json
import os
from dotenv import load_dotenv
import logging

# Initialize logger
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO)

# Load environment variables from the .env file
load_dotenv()

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")

# Check for missing environment variables
if not aws_access_key or not aws_secret_key or not region_name:
    logger.error("Missing AWS credentials or region name in environment variables.")
    raise ValueError("Missing AWS credentials or region name in environment variables.")

# Establish a session with AWS
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)

# Create an ELB client
elb_client = session.client('elbv2')

# Load instance and security group IDs from JSON file
with open('instance_ids.json', 'r') as f:
    data = json.load(f)
    instance_ids = data['instance_ids']
    security_group_ids = data['security_group_ids']

# Retrieve the load balancer ARN and DNS name
load_balancers = elb_client.describe_load_balancers()
load_balancer_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
load_balancer_dns_name = load_balancers['LoadBalancers'][0]['DNSName']

print(f"Load Balancer DNS Name: {load_balancer_dns_name}")

# Create an ACM client
acm_client = session.client('acm')

# Request a new certificate using the load balancer DNS name
response = acm_client.request_certificate(
    DomainName=load_balancer_dns_name,
    ValidationMethod='DNS'
)

certificate_arn = response['CertificateArn']
print("Certificate ARN:", certificate_arn)

# Retrieve the listener ARN
listeners = elb_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
listener_arn = listeners['Listeners'][0]['ListenerArn']

# Retrieve the target group ARN for Tomcat instances
target_groups = elb_client.describe_target_groups(LoadBalancerArn=load_balancer_arn)
tomcat_target_group_arn = None
for tg in target_groups['TargetGroups']:
    if 'tomcat' in tg['TargetGroupName'].lower():
        tomcat_target_group_arn = tg['TargetGroupArn']
        break

if not tomcat_target_group_arn:
    logger.error("Tomcat target group ARN not found.")
    raise ValueError("Tomcat target group ARN not found.")

# Create a new listener with SSL configuration
response = elb_client.create_listener(
    LoadBalancerArn=load_balancer_arn,
    Protocol='HTTPS',
    Port=443,
    SslPolicy='ELBSecurityPolicy-2016-08',
    Certificates=[
        {
            'CertificateArn': certificate_arn
        },
    ],
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': tomcat_target_group_arn
        }
    ]
)

print("SSL listener created:", response)

