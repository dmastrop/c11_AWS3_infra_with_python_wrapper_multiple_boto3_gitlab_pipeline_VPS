
import boto3
from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime
import sys

# Set up logging
logging.basicConfig(level=logging.DEBUG)  # Change to DEBUG level
logger = logging.getLogger(__name__)

# Load environment variables from the .env file
load_dotenv()

# Confirm script execution
print("Script started")  # This should print

# Debug statement before setting variables
logger.debug("Before setting environment variables")

