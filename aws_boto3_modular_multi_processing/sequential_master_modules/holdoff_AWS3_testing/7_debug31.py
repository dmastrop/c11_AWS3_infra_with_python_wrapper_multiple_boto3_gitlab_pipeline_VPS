import boto3
from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from the .env file
load_dotenv()


# Confirm script execution
print("Script started")



# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")

# Check for missing environment variables
if not aws_access_key or not aws_secret_key or not region_name:
    logger.error("Missing AWS credentials or region name in environment variables.")
    raise ValueError("Missing AWS credentials or region name in environment variables.")

# Establish a session with AWS

logger.info("Establishing a session with AWS...")

session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region_name
)


logger.info("Session established successfully.")

