import os
import subprocess
import time

def run_python_scripts_sequentially(directory, delay_seconds):
    # List all files in the specified directory in the order of ls -la
    files = sorted(os.listdir(directory))
    
    # Filter out only Python scripts
    python_scripts = [f for f in files if f.endswith('.py')]
    
    # Run each Python script in the order they appear in the directory
    for script in python_scripts:
        script_path = os.path.join(directory, script)
        print(f"Running {script_path}...")
        result = subprocess.run(['python3', script_path], capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)
        
        # Introduce a delay
        time.sleep(delay_seconds)

if __name__ == "__main__":
    # Specify the directory containing the Python scripts
    directory = '/aws_EC2/sequential_master'
    run_python_scripts_sequentially(directory, delay_seconds=90)
# test5
