
import boto3
from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime
import sys

# Set up logging
logging.basicConfig(level=logging.DEBUG)  # Changed to DEBUG for more detailed logging
logger = logging.getLogger(__name__)

# Load environment variables from the .env file
load_dotenv()

# Confirm script execution
try:
    print("Script started")
    sys.stdout.flush()
except Exception as e:
    print(f"An error occurred: {e}")

# Print Python version
print(f"Python version: {sys.version}")
sys.stdout.flush()

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")

# Print environment variables for verification
print(f"AWS Access Key: {aws_access_key}")
print(f"AWS Secret Key: {aws_secret_key}")
print(f"Region Name: {region_name}")
sys.stdout.flush()

# Check for missing environment variables
if not aws_access_key or not aws_secret_key or not region_name:
    logger.error("Missing AWS credentials or region name in environment variables.")
    raise ValueError("Missing AWS credentials or region name in environment variables.")

# Establish a session with AWS
logger.info("Establishing a session with AWS...")
print("Establishing a session with AWS...")
sys.stdout.flush()

try:
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region_name
    )
    logger.info("Session established successfully.")
    print("Session established successfully")
    sys.stdout.flush()
except Exception as e:
    logger.error(f"Failed to establish session: {e}")
    print(f"Failed to establish session: {e}")
    sys.stdout.flush()
    sys.exit(1)

