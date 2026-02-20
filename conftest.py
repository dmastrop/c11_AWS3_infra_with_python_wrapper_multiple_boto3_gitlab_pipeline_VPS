import sys
import os

# Absolute path to the repo root
ROOT = os.path.dirname(os.path.abspath(__file__))

# Absolute path to the correct package root
PACKAGE_ROOT = os.path.join(ROOT, "aws_boto3_modular_multi_processing")

# 1. Remove any shadow copies of sequential_master_modules
sys.path = [p for p in sys.path if "sequential_master_modules" not in p]

# 2. Ensure the correct package root is FIRST
sys.path.insert(0, PACKAGE_ROOT)

