import os
import subprocess
import time

def run_python_scripts_sequentially(directory, delays):
    # List all files in the specified directory in the order of ls -la
    files = sorted(os.listdir(directory))
    
    # Filter out only Python scripts
    python_scripts = [f for f in files if f.endswith('.py')]
    
    all_outputs = []  # Collect outputs of all scripts
    
    # Run each Python script in the order they appear in the directory
    for i, script in enumerate(python_scripts):
        script_path = os.path.join(directory, script)
        print(f"Running {script_path}...")
        
        # Run the script and capture output in binary mode
        result = subprocess.run(['python3', script_path], capture_output=True)
        stdout = result.stdout.decode('utf-8', errors='ignore')
        stderr = result.stderr.decode('utf-8', errors='ignore')
        
        # Clean up the output by replacing '\\n' with actual new lines
        cleaned_output = stdout.replace('\\n', '\n')
        
        # Collect the cleaned output
        all_outputs.append(cleaned_output)
        
        # Introduce a delay if it's not the last script
        if i < len(python_scripts) - 1:
            print(f"Delaying next execution by {delays[i]} seconds...")
            time.sleep(delays[i])
    
    return all_outputs

if __name__ == "__main__":
    # Specify the directory containing the Python scripts
    directory = '/aws_EC2/sequential_master'  # Replace with actual directory path
    
    # Specify the delays between running each script
    delays = [5, 1, 90, 10, 90]  # Replace with actual delay values
    
    outputs = run_python_scripts_sequentially(directory, delays)
    for output in outputs:
        print(output)

