import sys
import os

# Absolute path to the directory containing the package
ROOT = os.path.dirname(os.path.abspath(__file__))

PACKAGE_ROOT = os.path.join(ROOT, "aws_boto3_modular_multi_processing")

# Ensure the package root is FIRST on sys.path
sys.path.insert(0, PACKAGE_ROOT)

