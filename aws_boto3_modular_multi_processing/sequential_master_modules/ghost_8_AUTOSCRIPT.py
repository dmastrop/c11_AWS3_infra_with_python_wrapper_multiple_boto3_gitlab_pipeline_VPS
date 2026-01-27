import boto3
import time

# -------- CONFIGURATION --------
REGION = "us-east-1"

AMI_ID = "ami-0c398cb65a93047f2"
INSTANCE_TYPE = "t2.micro"
KEY_NAME = "generic_keypair_for_python_testing"
SECURITY_GROUP_ID = "sg-0a1f89717193f7896"
VPC_ID = "vpc-0a11e68402b1fa2f3"

COUNT = 8
SUBNET_ID = None   # Auto-detect default subnet unless you set this manually
# --------------------------------

ec2 = boto3.client("ec2", region_name=REGION)


def get_default_subnet(vpc_id):
    """Return the first subnet in the VPC if SUBNET_ID is not provided."""
    resp = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    if not resp["Subnets"]:
        raise RuntimeError("No subnets found in VPC")
    return resp["Subnets"][0]["SubnetId"]


def create_single_ghost(name, subnet):
    print(f"Launching {name}...")

    resp = ec2.run_instances(
        ImageId=AMI_ID,
        InstanceType=INSTANCE_TYPE,
        KeyName=KEY_NAME,
        MaxCount=1,
        MinCount=1,
        NetworkInterfaces=[
            {
                "DeviceIndex": 0,
                "SubnetId": subnet,
                "Groups": [SECURITY_GROUP_ID],
                "AssociatePublicIpAddress": True
            }
        ],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": name}]
            }
        ]
    )

    inst = resp["Instances"][0]
    iid = inst["InstanceId"]

    # Wait a moment for IPs to populate
    time.sleep(2)

    desc = ec2.describe_instances(InstanceIds=[iid])
    inst_info = desc["Reservations"][0]["Instances"][0]

    pub = inst_info.get("PublicIpAddress")
    priv = inst_info.get("PrivateIpAddress")

    print(f"{name}: {iid} public={pub}, private={priv}")
    return iid


def create_ghost_instances():
    subnet = SUBNET_ID or get_default_subnet(VPC_ID)
    print(f"Using subnet: {subnet}")

    instance_ids = []
    for i in range(1, COUNT + 1):
        name = f"ghost{i}"
        iid = create_single_ghost(name, subnet)
        instance_ids.append(iid)

    print("\nAll ghosts launched:")
    print(instance_ids)
    return instance_ids


if __name__ == "__main__":
    ids = create_ghost_instances()
    print("\nDone.")

