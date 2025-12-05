# utils.py
# These functions are used in both module2e and 2f so far

import boto3
import os
import time



def log_ghost_context(entry, reason):
    """
    Append ghost-specific forensic context tags to a registry entry.
    Does not change status, only adds tags for analytics clarity.
    """
    entry.setdefault("tags", [])
    entry["tags"].append(f"ghost_context:{reason}")
    return entry

#### add the _extract_instance_id function that is used by teh resolve_instance_id function below. These are both from module2f
def _extract_instance_id(describe_resp):
    """
    Helper to pull InstanceId out of AWS describe_instances response.
    """
    for r in describe_resp.get("Reservations", []):
        for i in r.get("Instances", []):
            iid = i.get("InstanceId")
            if iid: return iid
    return None


#### This helper function is used for the InstanceId decison logic (in the ghost handler function process_ghost in module2e)
def resolve_instance_id(public_ip=None, private_ip=None, region=None):
    """
    Resolve the current InstanceId live from AWS.
    - Prefer public IP lookup (most stable for resurrection).
    - Fallback to private IP if public is missing.
    - This ensures we always get the *current* instance_id, even if IPs were recycled.
    """
    session = boto3.Session(region_name=region or os.getenv("region_name"))
    ec2 = session.client("ec2")

    # Try public IP filter first
    if public_ip:
        resp = ec2.describe_instances(
            Filters=[{"Name": "ip-address", "Values": [public_ip]}]
        )
        iid = _extract_instance_id(resp)
        if iid: return iid

    # Fallback: try private IP filter
    if private_ip:
        resp = ec2.describe_instances(
            Filters=[{"Name": "network-interface.addresses.private-ip-address",
                      "Values": [private_ip]}]
        )
        iid = _extract_instance_id(resp)
        if iid: return iid

    print(f"[module2f] InstanceId not found for IPs public={public_ip}, private={private_ip}")
    return None


#### These helper functions are to reboot a node and check that status and instance health checks on the node
#### These functions are used especially in the module2e handler blocks (for example in the process_ghost handler for ghost ips)
#### when the instance_id is available. Ghost ips are always rebooted prior to resurrection. These functions will be used in 
#### other handlers in module2e as the code evolves.
def reboot_instance(instance_id, region=None, max_wait=300, poll_interval=15):
    """
    Reboot a single EC2 instance and wait until it is healthy.
    Returns True if reboot succeeded and health checks passed, False otherwise.
    """
    session = boto3.Session(region_name=region or os.getenv("region_name"))
    ec2 = session.client("ec2")

    try:
        ec2.reboot_instances(InstanceIds=[instance_id])
        print(f"[utils] Reboot initiated for {instance_id}")

        waited = 0
        while waited < max_wait:
            resp = ec2.describe_instance_status(InstanceIds=[instance_id])
            statuses = resp.get("InstanceStatuses", [])
            if statuses:
                inst_status = statuses[0]["InstanceStatus"]["Status"]
                sys_status = statuses[0]["SystemStatus"]["Status"]
                if inst_status == "ok" and sys_status == "ok":
                    print(f"[utils] Instance {instance_id} passed 2/2 checks")
                    return True
            time.sleep(poll_interval)
            waited += poll_interval

        print(f"[utils] Timeout waiting for {instance_id} to become healthy")
        return False

    except Exception as e:
        print(f"[utils] Error rebooting {instance_id}: {e}")
        return False


def health_check_instance(instance_id, region=None):
    """
    Perform a lightweight health check (2/2 status checks).
    Returns True if healthy, False otherwise.
    """
    session = boto3.Session(region_name=region or os.getenv("region_name"))
    ec2 = session.client("ec2")

    try:
        resp = ec2.describe_instance_status(InstanceIds=[instance_id])
        statuses = resp.get("InstanceStatuses", [])
        if statuses:
            inst_status = statuses[0]["InstanceStatus"]["Status"]
            sys_status = statuses[0]["SystemStatus"]["Status"]
            return inst_status == "ok" and sys_status == "ok"
        return False
    except Exception as e:
        print(f"[utils] Error checking health for {instance_id}: {e}")
        return False

