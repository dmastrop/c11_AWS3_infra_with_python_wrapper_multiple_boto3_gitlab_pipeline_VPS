
import boto3
from dotenv import load_dotenv
import os
import logging

# Set up logging
try:
    logging.basicConfig(level=logging.DEBUG)  # Change to DEBUG level
    logger = logging.getLogger(__name__)
    print("Logging setup successful")
except Exception as e:
    print(f"Logging setup failed: {e}")

# Load environment variables from the .env file
try:
    load_dotenv()
    print("Environment variables loaded")
except Exception as e:
    print(f"Failed to load environment variables: {e}")

# Confirm script execution
print("Script started")  # This should print

# Debug statement before setting variables
try:
    logger.debug("Before setting environment variables")
    print("Debug statement executed")
except Exception as e:
    print(f"Failed to execute debug statement: {e}")

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")

# Print out specific environment variables for debugging
print(f"AWS_ACCESS_KEY_ID: {aws_access_key}")
print(f"AWS_SECRET_ACCESS_KEY: {aws_secret_key}")
print(f"region_name: {region_name}")

# Check for missing environment variables
if not aws_access_key or not aws_secret_key or not region_name:
    print("Missing AWS credentials or region name in environment variables.")
    raise ValueError("Missing AWS credentials or region name in environment variables.")

# Establish a session with AWS
print("Establishing a session with AWS...")

try:
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    print("Session established successfully.")
except Exception as e:
    print(f"Failed to establish session: {e}")
    raise

# Confirm script completion
print("Script completed")

