import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

def run_python_script(script_path):
    print(f"Running {script_path}...")
    try:
        # Run the script and capture output in binary mode
        result = subprocess.run(['python3', script_path], capture_output=True, text=True)
        stdout = result.stdout
        stderr = result.stderr
        
        # Print the output immediately
        print(stdout)
        if stderr:
            print(stderr)
    except Exception as e:
        print(f"An error occurred while running {script_path}: {e}")

def run_python_scripts(directory, delays, parallel_ranges):
    # List all files in the specified directory in the order of ls -la
    files = sorted(os.listdir(directory))
    
    # Filter out only Python scripts
    python_scripts = [f for f in files if f.endswith('.py')]

    i = 0
    while i < len(python_scripts):
        # Check if the current index falls within any of the parallel ranges
        parallel_range = next((r for r in parallel_ranges if r[0] <= i <= r[1]), None)
        
        if parallel_range:
            # Run scripts within the parallel range using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=(parallel_range[1] - parallel_range[0] + 1)) as executor:
                futures = []
                for j in range(parallel_range[0], parallel_range[1] + 1):
                    if j < len(python_scripts):
                        script_path = os.path.join(directory, python_scripts[j])
                        futures.append(executor.submit(run_python_script, script_path))
                        if j < len(python_scripts) - 1:
                            print(f"Delaying next execution by {delays[j]} seconds...")
                            time.sleep(delays[j])
                # # Wait for all futures to complete before moving to the next file. This is very important.
                # We do not want to proceed with the next file (sequential) until all the parallel files in 
                # this range tuple are complete.
                for future in futures:
                    future.result()
            i = parallel_range[1] + 1
        else:
            # Run scripts sequentially if not in parallel range
            script_path = os.path.join(directory, python_scripts[i])
            run_python_script(script_path)
            if i < len(python_scripts) - 1:
                print(f"Delaying next execution by {delays[i]} seconds...")
                time.sleep(delays[i])
            i += 1

if __name__ == "__main__":
    # Specify the directory containing the Python scripts
    directory = '/aws_EC2/sequential_master'  # Replace with actual directory path
    
    # Specify the delays between running each script
    delays = [5, 20, 90, 10, 90, 20, 20, 20, 20, 20, 20, 20, 20, 20]  # Replace with actual delay values
    
    # Specify the ranges of indices of files to run in parallel (0-based index)
    #parallel_ranges = [(3, 4), (7, 8)]
    #parallel_ranges = [(3, 5), (7, 8)]

    # for intial test just run beanstalk and RDS in parallel and then run the jumphost sequentially after them
    #parallel_ranges = [(0, 1)]
    parallel_ranges = [(0, 1), (2,4)]
    run_python_scripts(directory, delays, parallel_ranges)

