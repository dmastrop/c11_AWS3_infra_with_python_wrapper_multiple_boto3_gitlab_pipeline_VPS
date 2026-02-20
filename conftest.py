import sys
import os

PACKAGE_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "aws_boto3_modular_multi_processing"
)

if PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, PACKAGE_ROOT)

