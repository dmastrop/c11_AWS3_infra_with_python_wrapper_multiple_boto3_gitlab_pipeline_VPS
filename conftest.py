import sys
import os

# Absolute path to the repo root
ROOT = os.path.dirname(os.path.abspath(__file__))

# Absolute path to the correct package root
PACKAGE_ROOT = os.path.join(ROOT, "aws_boto3_modular_multi_processing")

# Remove ONLY shadow paths that end with sequential_master_modules
sys.path = [
    p for p in sys.path
    if not p.endswith("sequential_master_modules")
]

# Ensure the correct package root is FIRST
if PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, PACKAGE_ROOT)

