import boto3
from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# Load instance IDs and security group IDs from the file
# This is from the EC2 instance creation and tomcat9 installation script that executes prior to this.  The instance_id
# and the security_group_ids are required to configure the ALB below.
with open('instance_ids.json', 'r') as f:
    data = json.load(f)
    instance_ids = data['instance_ids']
    security_group_ids = data['security_group_ids']

# Create a target group. Note that the default port of 8080 is configured on the EC2 instances
logger.info("Creating target group...")
target_group = elb_client.create_target_group(
    Name='tomcat-target-group',
    Protocol='HTTP',
    Port=8080,
    VpcId='vpc-009db827e48cf8c7b',  # Replace with your VPC ID. Using default VPC here.
    HealthCheckProtocol='HTTP',
    HealthCheckPort='8080',
    HealthCheckPath='/',
    HealthCheckIntervalSeconds=30,
    HealthCheckTimeoutSeconds=5,
    HealthyThresholdCount=5,
    UnhealthyThresholdCount=2,
    TargetType='instance'
)
logger.info("Target group created successfully.")

target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']

# Register instances with the target group.  The instance_id from instance_ids list have been imported from the 
# previous python script as noted above using json (import json library).
logger.info("Registering instances with the target group...")
targets = [{'Id': instance_id} for instance_id in instance_ids]
elb_client.register_targets(TargetGroupArn=target_group_arn, Targets=targets)
logger.info("Instances registered successfully.")

# Create the load balancer
# Note this: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2/client/create_load_balancer.html
# [Application Load Balancers] You must specify subnets from at least two Availability Zones.
# The security_group_ids list has 8080 allow all already 
# The subnets are the private subnets. The EC2 instances all have public and private ip addresses so this should be fine.
logger.info("Creating load balancer...")
load_balancer = elb_client.create_load_balancer(
    Name='tomcat-load-balancer',
    Subnets=['subnet-0e34b914c08ba8bd5', 'subnet-09638c6f9b996a855', 'subnet-092198dd41287da22', 'subnet-0183921fc71694caa', 'subnet-06840adffc6b5353e', 'subnet-005a6e9eec2a0087b' ],  # Replace with your subnet IDs
    SecurityGroups=security_group_ids,
    Scheme='internet-facing',
    Tags=[{'Key': 'Name', 'Value': 'tomcat-load-balancer'}],
    Type='application',
    IpAddressType='ipv4'
)
logger.info("Load balancer created successfully.")

load_balancer_arn = load_balancer['LoadBalancers'][0]['LoadBalancerArn']

# Create a listener for the load balancer
logger.info("Creating listener for the load balancer...")
listener = elb_client.create_listener(
    LoadBalancerArn=load_balancer_arn,
    Protocol='HTTP',
    Port=80,
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': target_group_arn
        }
    ]
)
logger.info("Listener created successfully.")

print("Application Load Balancer and listener created successfully.")


# Enable access logs for the load balancer
logger.info("Enabling access logs for the load balancer...")
elb_client.modify_load_balancer_attributes(
    LoadBalancerArn=load_balancer_arn,
    Attributes=[
        {
            'Key': 'access_logs.s3.enabled',
            'Value': 'true'
        },
        {
            'Key': 'access_logs.s3.bucket',
            'Value': 's3-python-alb-logs'
        },
        {
            'Key': 'access_logs.s3.prefix',
            'Value': 'test'
        }
    ]
)
logger.info("Access logs enabled successfully.")


# error due to the presence of `datetime` objects in the response from AWS, which are not directly serializable to JSON. To# fix this, use a custom serializer for `datetime` objects with the function below and call this function when doing the
# printing of the describe data sets below
def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError ("Type not serializable")

def print_json(data):
    """Print JSON data in a more presentable and easier to read way"""
    print(json.dumps(data, indent=4, default=json_serial))


# Describe load balancers
logger.info("Describing load balancers...")
load_balancers_description = elb_client.describe_load_balancers()
print_json(load_balancers_description)



# Describe load balancer attributes
logger.info("Describing load balancer attributes...")
load_balancer_attributes_description = elb_client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer_arn)
print_json(load_balancer_attributes_description)



# Describe target groups
logger.info("Describing target groups...")
target_groups_description = elb_client.describe_target_groups()
print_json(target_groups_description)



# Describe target group attributes
logger.info("Describing target group attributes...")
target_group_attributes_description = elb_client.describe_target_group_attributes(TargetGroupArn=target_group_arn)
print_json(target_group_attributes_description)



# Describe listeners
# note that the load_balancer_arn has already been defined earlier, see above when listener was created
logger.info("Describing listeners...")
listeners_description = elb_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
print_json(listeners_description)



# Describe listener attributes
# note that need to define the listener_arn. It has not been defined yet.
listener_arn = listeners_description['Listeners'][0]['ListenerArn']
logger.info("Describing listener attributes...")
listener_attributes_description = elb_client.describe_listener_attributes(ListenerArn=listener_arn)
print_json(listener_attributes_description)





# Add the pretty format of the above

def print_formatted_output(data):
    """Print formatted output for better readability"""

    def format_load_balancers(load_balancers):
        for lb in load_balancers:
            print(f"### Load Balancers")
            print(f"**Load Balancer ARN:** {lb['LoadBalancerArn']}")
            print(f"**DNS Name:** {lb['DNSName']}")
            print(f"**Created Time:** {lb['CreatedTime']}")
            print(f"**Load Balancer Name:** {lb['LoadBalancerName']}")
            print(f"**Scheme:** {lb['Scheme']}")
            print(f"**VPC ID:** {lb['VpcId']}")
            print(f"**State:** {lb['State']['Code']}")
            print(f"**Type:** {lb['Type']}")
            print(f"**Availability Zones:**")
            for az in lb['AvailabilityZones']:
                print(f"- {az['ZoneName']} ({az['SubnetId']})")
            print(f"**Security Groups:** {', '.join(lb['SecurityGroups'])}")
            print(f"**IP Address Type:** {lb['IpAddressType']}")
            print(f"**Enable Prefix for IPv6 Source NAT:** {lb['EnablePrefixForIpv6SourceNat']}")
            print()

    def format_load_balancer_attributes(attributes):
        print(f"### Load Balancer Attributes")
        for attr in attributes:
            print(f"**{attr['Key']}:** {attr['Value']}")
        print()

    def format_target_groups(target_groups):
        for tg in target_groups:
            print(f"### Target Groups")
            print(f"**Target Group ARN:** {tg['TargetGroupArn']}")
            print(f"**Target Group Name:** {tg['TargetGroupName']}")
            print(f"**Protocol:** {tg['Protocol']}")
            print(f"**Port:** {tg['Port']}")
            print(f"**VPC ID:** {tg['VpcId']}")
            print(f"**Health Check Protocol:** {tg['HealthCheckProtocol']}")
            print(f"**Health Check Port:** {tg['HealthCheckPort']}")
            print(f"**Health Check Enabled:** {tg['HealthCheckEnabled']}")
            print(f"**Health Check Interval:** {tg['HealthCheckIntervalSeconds']} seconds")
            print(f"**Health Check Timeout:** {tg['HealthCheckTimeoutSeconds']} seconds")
            print(f"**Healthy Threshold Count:** {tg['HealthyThresholdCount']}")
            print(f"**Unhealthy Threshold Count:** {tg['UnhealthyThresholdCount']}")
            print(f"**Health Check Path:** {tg['HealthCheckPath']}")
            print(f"**Matcher:** {tg['Matcher']['HttpCode']}")
            print(f"**Load Balancer ARNs:** {', '.join(tg['LoadBalancerArns'])}")
            print(f"**Target Type:** {tg['TargetType']}")
            print(f"**Protocol Version:** {tg.get('ProtocolVersion', 'N/A')}")
            print(f"**IP Address Type:** {tg['IpAddressType']}")
            print()

    def format_target_group_attributes(attributes):
        print(f"### Target Group Attributes")
        for attr in attributes:
            print(f"**{attr['Key']}:** {attr['Value']}")
        print()

    def format_listeners(listeners):
        for listener in listeners:
            print(f"### Listeners")
            print(f"**Listener ARN:** {listener['ListenerArn']}")
            print(f"**Load Balancer ARN:** {listener['LoadBalancerArn']}")
            print(f"**Port:** {listener['Port']}")
            print(f"**Protocol:** {listener['Protocol']}")
            for action in listener['DefaultActions']:
                print(f"**Default Actions:** {action['Type']} to target group {action['TargetGroupArn']}")
            print()

    def format_listener_attributes(attributes):
        print(f"### Listener Attributes")
        for attr in attributes:
            print(f"**{attr['Key']}:** {attr['Value']}")
        print()

    if 'LoadBalancers' in data:
        format_load_balancers(data['LoadBalancers'])
    if 'Attributes' in data:
        format_load_balancer_attributes(data['Attributes'])
    if 'TargetGroups' in data:
        format_target_groups(data['TargetGroups'])
    if 'TargetGroupAttributes' in data:
        format_target_group_attributes(data['TargetGroupAttributes'])
    if 'Listeners' in data:
        format_listeners(data['Listeners'])
    if 'ListenerAttributes' in data:
        format_listener_attributes(data['ListenerAttributes'])


# call the print_formatted_output function above to actually print out the pretty format.  They are called one at a time
# using the if blocks above in the print_formatted_output function, if the relevant data is present, i.e.
# LoadBalancers or Attributes, or TargetGroups, orTargetGroupAttributes, or ListenerAttributes

# Describe load balancers
logger.info("Describing load balancers...")
load_balancers_description = elb_client.describe_load_balancers()
print_formatted_output(load_balancers_description)

# Describe load balancer attributes
logger.info("Describing load balancer attributes...")
load_balancer_attributes_description = elb_client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer_arn)
print_formatted_output(load_balancer_attributes_description)

# Describe target groups
logger.info("Describing target groups...")
target_groups_description = elb_client.describe_target_groups()
print_formatted_output(target_groups_description)

# Describe target group attributes
logger.info("Describing target group attributes...")
target_group_attributes_description = elb_client.describe_target_group_attributes(TargetGroupArn=target_group_arn)
print_formatted_output(target_group_attributes_description)

# Describe listeners
logger.info("Describing listeners...")
listeners_description = elb_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
print_formatted_output(listeners_description)

# Describe listener attributes
listener_arn = listeners_description['Listeners'][0]['ListenerArn']
logger.info("Describing listener attributes...")
listener_attributes_description = elb_client.describe_listener_attributes(ListenerArn=listener_arn)
print_formatted_output(listener_attributes_description)

