# utils.py
# These functions are used in both module2e and 2f so far


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


#### This helper function is used for the InstanceId decison logic (in the ghost handler function process_ghost
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

