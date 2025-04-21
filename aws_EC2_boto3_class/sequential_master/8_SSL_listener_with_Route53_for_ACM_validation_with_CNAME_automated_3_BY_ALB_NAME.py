import boto3
import json
import os
from dotenv import load_dotenv
import logging
import time
import sys

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
# add ec2_client since we have to add port 443 to the security group.
ec2_client = session.client('ec2')



# Load instance and security group IDs from JSON file
with open('instance_ids.json', 'r') as f:
    data = json.load(f)
    instance_ids = data['instance_ids']
    security_group_ids = data['security_group_ids']

# Retrieve the load balancer ARN and DNS name
## THIS does not work because when have multiple loadbalancers referencing by indes[0] could get the wrong one
## when the beanstalk loadbalancer is added, this problem was encountered. For this script best to refer to
## the loadbalancer by name to remove any such errors from occurring. For beanstalk script will have to refer
## to it by beanstalk dynamic name rather that [0] so that we don't refer to wrong load balancer.
#load_balancers = elb_client.describe_load_balancers()
#load_balancer_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
#load_balancer_dns_name = load_balancers['LoadBalancers'][0]['DNSName']

# Retrieve the load balancer ARN by name 'tomcat-load-balancer'
load_balancers = elb_client.describe_load_balancers()
load_balancer_arn = None

for lb in load_balancers['LoadBalancers']:
    if lb['LoadBalancerName'] == 'tomcat-load-balancer':
        load_balancer_arn = lb['LoadBalancerArn']
        load_balancer_dns_name = lb['DNSName']
        break

if load_balancer_arn is None:
    raise ValueError("Load balancer 'tomcat-load-balancer' not found")


print(f"Load Balancer DNS Name: {load_balancer_dns_name}")
print(f"Load Balancer arn: {load_balancer_arn}")
sys.stdout.flush()


# Add A record for the ALB DNS name to Route53 hosted zone as a routed A record
hosted_zone_id = 'Z053493128WBD2P6V1KLG'  # Replace with your Route 53 hosted zone ID
route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={
        'Changes': [
            {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': 'loadbalancer1.holinessinloveofchrist.com',
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': 'Z35SXDOTRQ7X7K',  # Hosted zone ID for the load balancer. This is not
                        # the same as the hosted_zone_id for Route53. .  The hosted zone ID for the loadbalancer  is a
                        # static value based upon the zone us-east-1 in this case
                        # see this link:   https://docs.aws.amazon.com/general/latest/gr/elb.html
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





# Request a new certificate using the custom DNS domain name
response = acm_client.request_certificate(
    DomainName='loadbalancer1.holinessinloveofchrist.com',
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
#hosted_zone_id = 'YOUR_ROUTE53_HOSTED_ZONE_ID'  # Replace with Route 53 hosted zone ID
hosted_zone_id = 'Z053493128WBD2P6V1KLG'  # Replace with your Route 53 hosted zone ID
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
sys.stdout.flush()




# Add security group rule to allow port 443 from anywhere (0.0.0.0/0)
for sg_id in security_group_ids:
       try:
               ec2_client.authorize_security_group_ingress(
                       GroupId=sg_id,
                    IpPermissions=[
                               {
                                       'IpProtocol': 'tcp',
                                       'FromPort': 443,
                                       'ToPort': 443,
                                       'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                               }
                       ]
               )
               print(f"Security group rule added to allow port 443 from anywhere for security group {sg_id}")
               sys.stdout.flush()
       except Exception as e:
               if "InvalidPermission.Duplicate" in str(e):
                       print(f"Security group rule already exists for port 443 in security group {sg_id}")
                       sys.stdout.flush()
               else:
                       print(f"An error occurred: {e}")
                       sys.stdout.flush()



# Need to automate the adding of the CNAME to route53 and then wait for ACM cert to be Issued state and only then create the HTTPS listener. Otherwise the cert is not valid and the listener will fail. Use the route53 class to add the CNAME info form the ACM class, and once the CNAME is added to route53 wait for the cert to be Issued state and only then create the 443 listener.   Note: will also have to add code to the default security group that the loadbalancer uses for port 443. 
# NOTE: the Route53 hosted zone  has to have an A record mapped to the DNS AWS URI. This can be automated as well. The CNAME addition to route53 is already automated. 

