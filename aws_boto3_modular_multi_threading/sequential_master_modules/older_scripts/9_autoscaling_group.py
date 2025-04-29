import boto3
import json
import os
from dotenv import load_dotenv
import logging
import time

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

# Create clients
elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')


# Retrieve the load balancer ARN and DNS name
load_balancers = elb_client.describe_load_balancers()
load_balancer_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
load_balancer_dns_name = load_balancers['LoadBalancers'][0]['DNSName']

print(f"Load Balancer DNS Name: {load_balancer_dns_name}")
print(f"Load Balancer ARN: {load_balancer_arn}")

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

print(f"Tomcat Target Group ARN: {tomcat_target_group_arn}")




# Load instance and security group IDs from JSON file
with open('instance_ids.json', 'r') as f:
    data = json.load(f)
    instance_ids = data['instance_ids']
    security_group_ids = data['security_group_ids']


# Subnet IDs for the default VPC
subnet_ids = ['subnet-0e34b914c08ba8bd5', 'subnet-09638c6f9b996a855', 'subnet-092198dd41287da22', 'subnet-0183921fc71694caa', 'subnet-06840adffc6b5353e', 'subnet-005a6e9eec2a0087b']

availability_zones = ['us-east-1a', 'us-east-1b', 'us-east-1c', 'us-east-1d', 'us-east-1e', 'us-east-1f']  # Replace with your actual Availability Zones


# Create Auto Scaling Group
autoscaling_client.create_auto_scaling_group(
    AutoScalingGroupName='my-auto-scaling-group',
    InstanceId=instance_ids[0],  # Use the first instance ID from your list
    MinSize=30,
    MaxSize=100,
    DesiredCapacity=35,
    VPCZoneIdentifier=','.join(subnet_ids),  # Use the subnet IDs here
    AvailabilityZones=availability_zones,  # Specify the Availability Zones
    TargetGroupARNs=[tomcat_target_group_arn],
    Tags=[
        {
            'Key': 'Name',
            'Value': 'my-auto-scaling-group'
        }
    ]
)

print("Auto Scaling Group created")



# Create a single scaling policy
autoscaling_client.put_scaling_policy(
    AutoScalingGroupName='my-auto-scaling-group',
    PolicyName='target-tracking-scaling-policy',
    PolicyType='TargetTrackingScaling',
    TargetTrackingConfiguration={
        'PredefinedMetricSpecification': {
            'PredefinedMetricType': 'ASGAverageCPUUtilization'
        },
        'TargetValue': 50.0,
        'DisableScaleIn': False  # Allow scaling in
    }
)

print("Scaling policy created")

