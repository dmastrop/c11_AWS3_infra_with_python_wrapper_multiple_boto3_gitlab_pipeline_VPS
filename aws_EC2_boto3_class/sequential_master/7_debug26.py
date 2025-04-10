
import os
from dotenv import load_dotenv
import json
from datetime import datetime
import sys

# Load environment variables from the .env file
load_dotenv()





# Confirm script execution
print("Script started")  # This should print

# Print environment variables
print("Environment Variables:")
for key, value in os.environ.items():
    print(f"{key}: {value}")

# Set variables from environment
aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region_name = os.getenv("region_name")

# Print out specific environment variables for debugging
print(f"AWS_ACCESS_KEY_ID: {aws_access_key}")
print(f"AWS_SECRET_ACCESS_KEY: {aws_secret_key}")
print(f"region_name: {region_name}")

