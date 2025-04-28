import os
import subprocess

def run_python_scripts_sequentially(directory):
    # List all files in the specified directory
    files = os.listdir(directory)
    
    # Filter out only Python scripts and sort them
    python_scripts = sorted([f for f in files if f.endswith('.py')])
    
    # Run each Python script in sequential order
    for script in python_scripts:
        script_path = os.path.join(directory, script)
        print(f"Running {script_path}...")
        result = subprocess.run(['python3', script_path], capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)

if __name__ == "__main__":
    # Specify the directory containing the Python scripts
    directory = '/home/ubuntu/course11_devops_startup_gitlab_repo/python_testing/AWS_infra_local_only/aws_EC2_boto3_class/sequential_master'
    run_python_scripts_sequentially(directory)
