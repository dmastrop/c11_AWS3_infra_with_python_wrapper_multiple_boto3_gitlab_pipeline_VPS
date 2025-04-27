import os
import subprocess
import time

def run_python_scripts_sequentially(directory, delays):
    # List all files in the specified directory in the order of ls -la
    files = sorted(os.listdir(directory))
    
    # Filter out only Python scripts
    python_scripts = [f for f in files if f.endswith('.py')]
    
    # Run each Python script in the order they appear in the directory
    for i, script in enumerate(python_scripts):
        script_path = os.path.join(directory, script)
        print(f"Running {script_path}...")
        
        #Original result:
        result = subprocess.run(['python3', script_path], capture_output=True, text=True)
        
        # try result in binary and manually decode in utf-8 as follows:
        #result = subprocess.run(['python3', script_path], capture_output=True)
        #stdout = result.stdout.decode('utf-8', errors='ignore')
        #stderr = result.stderr.decode('utf-8', errors='ignore')

        print(result.stdout)
        print(result.stderr)
        
        # Clean up the output by replacing '\\n' with actual new lines
        #cleaned_output = stdout.replace('\\\\n', '\\n')
    
        #return cleaned_output


        
        # Introduce a delay if it's not the last script
        if i < len(python_scripts) - 1:
            print(f"Delaying next execution by {delays[i]} seconds...")
            time.sleep(delays[i])

if __name__ == "__main__":

    # Specify the directory containing the Python scripts
    directory = '/aws_EC2/sequential_master' # Replace with actual directory path
    
    # Specify the delays between running each script
    delays = [5, 1, 90, 10, 90]  # Replace with actual delay values
    # the first number in the array is delay before file 2, is the actual delay before file 3 so this is the wait time for file 2, so use 20, 360, 90 for the delay for first, second, and third files.
# add 360,90 delays for scripts 5 and 6 for the ssh and tomcat installation
# REDUCED 360 to 5 to test the new status check and state check code in the SSH block
    run_python_scripts_sequentially(directory, delays)




# test9
