def restart_ec_multiple_instances():
    import boto3
    from dotenv import load_dotenv
    import os
    import sys
    import json
    from datetime import datetime



    # This will load env vars from the .env file
    # They will be available to use in the rest of the code blocks below
    load_dotenv()

    # Set variables
    # os.getenv will load from the .env. The .env will be created on the fly by the gitlab pipeline script
    aws_access_key = f'{os.getenv("AWS_ACCESS_KEY_ID")}'
    aws_secret_key = f'{os.getenv("AWS_SECRET_ACCESS_KEY")}'
    region_name = f'{os.getenv("region_name")}'
    image_id = f'{os.getenv("image_id")}'
    instance_type = f'{os.getenv("instance_type")}'
    key_name = f'{os.getenv("key_name")}'
    min_count = f'{os.getenv("min_count")}'
    max_count = f'{os.getenv("max_count")}'

    ## Define the sg_id that is used for the ORCHESTRATINO_LEVEL_SG_ID that is defined in the .gitlab-ci.yml file
    ## this is used in the start_ec2_instances function below
    sg_id = os.getenv("ORCHESTRATION_LEVEL_SG_ID")
    if not sg_id:
        raise RuntimeError("ORCHESTRATION_LEVEL_SG_ID is not set in environment")


    # Debugging: Print the loaded environment variables
    print("AWS Access Key:", aws_access_key)
    print("AWS Secret Key:", aws_secret_key)
    print("Region Name:", region_name)
    print("Image ID:", image_id)
    print("Instance Type:", instance_type)
    print("Key Name:", key_name)
    print("Min Count:", min_count)
    print("Max Count:", max_count)
    print("Orchestration_level_SG_ID:", sg_id)

    def start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count):
        # multi-threading is encountering scope issues again. Need to import boto3 inside the function
        import boto3
        import sys

        # Establish a session with AWS
        try:
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region_name
            )
            print("AWS session established.")
        except Exception as e:
            print("Error establishing AWS session:", e)
            sys.exit(1)
        
        # Create an EC2 client
        try:
            my_ec2 = session.client('ec2')
            print("EC2 client created.")
        except Exception as e:
            print("Error creating EC2 client:", e)
            sys.exit(1)
        
        # Start EC2 instances
        try:
            response = my_ec2.run_instances(
                ImageId=image_id,
                InstanceType=instance_type,
                KeyName=key_name,
                
                #SecurityGroupIds=['sg-0a1f89717193f7896'],  
                # Specify SG explicitly. For now i am using the default SG so all authorize_security_group_ingress method callls
                # will be applied to the default security group. The method is used to apply rules to the security group. This 
                # security group will be used on all the  nodes in the execution run.

                SecurityGroupIds=[sg_id],   ## sg_id is defined above from the ORCHESTRATION_LEVEL_SG_ID ENV variable
                ## Use this instead of hardcoding above 
                
                MinCount=int(min_count),
                MaxCount=int(max_count),
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'BatchID', 'Value': 'test-2025-08-13'},
                            {'Key': 'Patch', 'Value': '7c'}
                        ]
                    }
                ]

            )
            print("EC2 instances started:", response)
        except Exception as e:
            print("Error starting EC2 instances:", e)
            sys.exit(1)
        
        return response

    response = start_ec2_instances(aws_access_key, aws_secret_key, region_name, image_id, instance_type, key_name, min_count, max_count)
    #print(response)


    # Print the response in a more readable format using json.dumps for pretty printing
    #print(json.dumps(response, indent=4))



    # Print the response in a more readable format
    if 'Instances' in response:
        for i, instance in enumerate(response['Instances']):
            print(f"Instance {i+1}:")
            print(f"  Instance ID: {instance['InstanceId']}")
            print(f"  Instance Type: {instance['InstanceType']}")
            print(f"  Image ID: {instance['ImageId']}")
            print(f"  State: {instance['State']['Name']}")
            print(f"  Private IP Address: {instance['PrivateIpAddress']}")
            print(f"  Subnet ID: {instance['SubnetId']}")
    else:
        print("No instances found in the response.")


if __name__ == "__main__":
    restart_ec_multiple_instances()

