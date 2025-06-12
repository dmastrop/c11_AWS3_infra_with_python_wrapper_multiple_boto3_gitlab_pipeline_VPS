## Current and latest development work

The parent directory has the Docker files and the gitlab-ci.yml file
Dockerfile_python_multi_processing is for the latest development gitlab pipeline.

All python (mastser_script.py) run in self contained Docker container on the VPS

The VPS also hosts a self-managed gitlab container from which the pipelines are run. This expedites the repetitive testing, 
especially for benchmarking the module2 (below).

Latest development work is in the aws_boto3_modular_multi_processing sub-directory
The master_script.py is in this directory

This has all the latest multi-threading and multi-processing code in the sequential_master_modules package(directory)

The current 11 modules in the package sequential_master_modules are multi-processed in the master_script.py

The key module is the "install tomcat"  module (module2 in the master_script.py) in the following directory
aws_boto3_modular_multi_processing/sequential_master_modules
Use the latest timestamp python file.

This has all the latest optimizations for the multi-processing and multi-threading and the latest benchmark upates below
pertain to the optmizations to this module.








## UPDATES: part 12: Hyper-scaling of processes (250, 400+ processes), benchmark testing and VPS swap tuning





## UPDATES: part 11: Initial Key insights into process hyperscaling (150, 200, 250, 300, 400 concurrent processes) (more to follow)

The 250 concurrent process point for the current setup (16GB RAM and 16GB of swap) seems to be where the inflection point in the process scaling dynamics changes. At 200 process the pooling was a detriment to total execution time whereas the increased AWS API contention and swap dynamics at the 250 process level become poor enough where the 250 without pooling becomes the slower of the execution times, and pooling helps alleviate API contention and improve swap dynamics.  In testing the 250 and 0 pooled test execution time is improved upon with 25 pooled processes, and that is improved upon with the 50 pooled processes and that is improved upon with the 75 pooled processes, etc....   I did not see this behavior at the 200 concurrent process (pooling and increasing pooling resulted in poorer execution time).

At this point we introduce monitoring kswapd0 on the VPS (can’t do this from the python container as psutil does not allow direct access to process level host metrics, only global metrics on the VPS like CPU, RAM and swap).   The script below is run concurrently with the python pipeline to provide additiona metrics so that we can understand why the dynamics above begin to develop at the 250 inflection point. Here is the simple python script that is run directly on the VPS host. NOTE that the script is run in a python venv. I did not want to risk corrupting the native python installation on the VPS because the VPS requires that for configuration from the ansible controller (the VPS can be dynamically configured via ansible from the controller and the ansible on the controller (as the ansible client) requires a specific python version and python environment to continue to work)

The ptyhon code for kswapd0 logging in the module2 itself is still there but it is commented out. If running the module natively and not in a container that code will provide relaible kswapd0 logging in parallel wiht all of the other process orchestartion main() level logging and individual process logs as described in previous sections below.



```

(venv_kswapd) [root@vps ~]# cat kswapd_monitor.py 
import time
import psutil
import logging

# Set up logging
logging.basicConfig(filename="/root/kswapd_monitor.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def monitor_kswapd(interval=60):
    """Monitor kswapd0 every 'interval' seconds"""
    logging.info("Starting kswapd0 monitoring script...")
    
    while True:
        found = False
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
            if proc.info['name'] == "kswapd0":
                found = True
                logging.info(f"kswapd0 detected - PID: {proc.info['pid']}, CPU Usage: {proc.info['cpu_percent']}%")

        if not found:
            logging.warning("kswapd0 not found - it may not be actively swapping.")

        time.sleep(interval)

# Adjust the interval based on your testing needs
monitor_kswapd(interval=15)
```

Simply tail the logs during each pipeline run. We can correlate the python modules stats (CPU, swap and RAM, etc). with the kswapd0 tail logs via the timestamps very effectively. This permits us to ascertain the swap dynamics of each different test scenario run in the pipeline so that we can understand why pooling becomes effective at lowering execution time at the 250 process level and not at the 200 level.
Correlating the kswapd0 with the other python intrinsic logs is key.


### Review of releavant variables and Notation and examples:

desired_count is the intial batch of processes that will be handled by the multi-processing aspect of module 2 of the package where the core of the multi-theading and multi-processing optimizations were made

chunk_size it the chunk of IPs of EC2 instances which make up a chunk on which the multi-threading worker will process

max_workers is the thread count for the ThreadPoolExecutor which will work on the chunk of EC2 instance IPs of chunk_size
This thead count always pertains to a single process

From extensive testing it is best to set the max_workers to be equal to or greater than chunk_size (oversubsribing the thread worker does not increase execution time).  If max_workers is less than chunk_size performance and execution time degrades accordingly.

Examples: 

Example 1:
With a chunk of chunk_size 1 and 250 EC2 instances there will be 250 processes of 1 thread each to work on the 250 chunks of chunk_size=1

Note that for short hand moving forward with updates the following will be used, for example:
250/0 represents a test with 250 concurrent processes in the intial batch with 0 processes pooled
250/25 represents a test with 250 processes and in this case 250  EC2 instances, but inital batch is 225 processes and 25 are pooled and queued
250/50 represents a test with 250 processes and in this case 250 EC2 instances, but initial batch is 200 processes and 50 are pooled and queued


Example 2:
With a chunk_size of 2 and 400 EC2 instances there will be 200 processes of 2 threads each to work on the 200 chunks of chunk_size=2

200/0 represents a test with 200 concurrent processes in the intial batch with 0 processes pooled
200/25 represents a test with 200 processes and in this case 400 EC2 instances, but inital batch is 175 processes and 25 are pooled and queued
200/50 represents a test with 200 processes and in this case 400 EC2 instances, but initial batch is 150 processes and 50 are pooled and queued


NOTE:
The number of actual EC2 instances does not impact performance significantly as long as max_workers is set to equal or greater than the chunk_size, because the ThreadPoolExecutor is very efficient and is not the primary bottleneck in the process hyperscaling testing.
Thus there are many permutations available for testing given that the number of EC2 instances can always be changed to support a particular process concurrency test.  This can offer cost savings (for example to get 200 processes use a chunk_size of 1 and run it with 200 EC2 instances rather than 200 processes with a chunk_size of 2 with 400 EC2 instances.



### AWS API contention and exponential backoff with jitter for retrying API calls:

For API contention with the security group rule assignments (call to AuthorizeSecurityGroupIngress by authorize_security_group_ingress method)
 the max_retries is a siginficant variable

This needs to be set to 10 for the higher process level tests because the number of retries often exceeds 5.  It can be increased to
whatever number is necessary to support the number of  processes and in general higher process concurrency requires a higer 
max_retries number. This is ok for the exponential backoff python code because the delay parameter is not changed at all and only
the retries is changed for these higher process level tests. This ensures that the higher pooling test (less concurrent processes)
are not unecessarily penalized (wth an increased delay parameter) when comparted to a non-pooling test in regards to API contention.
If a higher concurrency is required it is intrinsically penalized because it will initiate and require more retries, whereas
the lower pooled tests will not require additional retries to the degree that fully concurrent tests do. This controls the 
tests when comparing pooled vs. non-pooled testing.

AWS recommends this exponential backoff, but a batch approach can also be considered as well. The max_retries simple solution below seems to be accomodating the higher process scaling well, and a batch approach will be considered if the number of retries becomes unruly for the hyper-scaling testing (400 and 800 processes).  With a batch approach we can essentially throttle and stagger the API requests (security group rule updates to each of the EC2 instances) into batches, batching the updates outside of the thread woker processing.

Note that for now the SG is the default SG and that can be chnaged in module1 of this python package.

random.uniform(0, 1) adds randomness (a jitter)  to prevent synchronized retries among multiple instances.

Randomness factors have been added throughout the python module, most notably for the process level logging so that we don't get storms of logging data fetches across all the parallel processes, or in this case a retry storm on the EC2 instance security group configuratino.  The random.uniform is the jitter addtion to the base exponential backoff.
((The logging was interesting. Prior to using randomness the logging was causing a deteriorition in the execution time (more on the process level logging is in the UPDATE main() logging  section below))

Without this, all retries could occur at the same exact intervals, causing a potential "retry storm.




```
def retry_with_backoff(func, max_retries=10, base_delay=1, max_delay=10, *args, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for AWS API call.")

```

This function above is used to wrap all the python calls to the authorize_security_group_ingress boto3 method that applies the SG 
rule to the SG (default for now) that is attached to each of the EC2 instances. The multi-processing and multi-threading
of this, makes this a requiremennt. Otherwise I see failed tomcat9 installatinons when the API is overwhelmed.

 Here is an example of the wrap for port 22 SSH rule applied to the default SG that is used on all the EC2 instances:


```
    for sg_id in set(security_group_ids):
        try:
            retry_with_backoff(
                my_ec2.authorize_security_group_ingress,
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
        except my_ec2.exceptions.ClientError as e:
            if 'InvalidPermission.Duplicate' in str(e):
                print(f"Rule already exists for security group {sg_id}")
            else:
                raise
```
This is working really well especially at the higher scale levels and the gitlab console logs can easily be searched for 
"Retry <seconds>" to ascertain the degree of API contention that is encountered by the script.



### Batch processing to deal with the API contention issue above:

I am going to leave in the current implementation with the exponential backoff and jitter becasue it is introducing an AWS delay 
factor that makes testing the tradeoffs between pooling the processes and not pooling the processes easy to demonstrate. The retries will penalize the non-pooled tests accordingly and this can be used as a general indicator of too much process contention causing a delay with AWS roll out.


The AWS limits are per account and not per request, so batching them together will distribute the load more evenly rather than massive API spikes encountered without the batch processing.

At a later stage the API contention issue will be approched using the batch processing with a worker thread as indicated below:
There are a lot of variants to this approach:


#### Method 1: Standard batch processing with a queue + a single background worker thread:

This appraoch uses a batch based upon a standard interval (2 seconds in this case), but can be optimized as shown further below, in case a static 2 second approach will not hold up with very high parallel process scenarios.

Each process in the current configuration creates 3 API requests with the authorize_seucrity_group_ingress method, one for port 22
one for port 80 and one for port 8080. This is designed this way so that it is extensible in the future for per process security
group rule customization (each process handles the chunk of chunk_size IPs and they will have similar rules in the security group)

Example of the batch processing: with 250 processes, and 3 rules to be configured in the security group, that is 750 API calls.
The worker thread will check the update_queue every 2 seconds, IF it is not working on anything. If it is
working on a batch it will have to complete the current batch, and then it will check and rab whatever is in the update_queue
since it last checked.  The for loop in the function causes this problem. It won't exit until all of the current batch is complete
and that leads to non-deterministic behavior.

This simple batch processing is prone to congestion because the batch sizes are not deterministic and the process timing for each
batch can get to be very high if a large accumulation occurs in the update_queue between worker thread processing.
In this way it is still prone to API congestion.

A solution is Method 2 below:  limiting batch size & adjusting the batch interval dynamically can help smooth out execution time and prevent request backlogs.  


```
import threading
import time

# Create the queue
update_queue = []
lock = threading.Lock()

def batch_security_group_updates():
    while True:
        time.sleep(2)  # Flush interval
        with lock:
            if update_queue:
                print(f"Processing {len(update_queue)} security group updates...")
                for sg_update in update_queue:
                    try:
                        my_ec2.authorize_security_group_ingress(**sg_update)
                    except my_ec2.exceptions.ClientError as e:
                        if 'InvalidPermission.Duplicate' in str(e):
                            print(f"Rule already exists for {sg_update['GroupId']}")
                        else:
                            raise
                update_queue.clear()  # Reset after processing




# Start worker thread
threading.Thread(target=batch_security_group_updates, daemon=True).start()


# Update the queue with the latest/current security group requests when the processes add rules to the SG(see example below)
def queue_security_group_update(GroupId, IpPermissions):
    with lock:
        update_queue.append({'GroupId': GroupId, 'IpPermissions': IpPermissions})




# Example usage:
for sg_id in set(security_group_ids):
    queue_security_group_update(sg_id, [{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }])
```

update_queue(Global List)  
   - Stores pending security group rule update requests form the parallel process rule configurations. This is a list of requests
that have  not actually been called using authorize_security_group_ingress
   - Updates accumulate here before they are processed in batches by the worker thread
   - Need the mutex (`lock`): ensures thread safety when worker thread is accessing the queue.

batch_security_group_updates() This is the Worker Thread  
   - This background thread constantly runs and checks for queued security group rule API request updates in update_queue  
   - If it is "stuck" processing a large batch of requests, it will be longer than 2 seconds before it grabs the next items from
the update_queue. This is the main drawback of this method. Batches can be highly variable and grow to large sizes.
   - Updates are applied via `my_ec2.authorize_security_group_ingress(**sg_update)`.  This actually updates the security group with the rules (in this case 22, 80 and 8080). This is done per process, hence the API congestion of accumulated API requests.
   - After processing, the queue is cleared, making room for new updates.  The queue has to completely clear prior to getting the new batch from the current update_queue.

queue_security_group_update() This actually Adds  Requests to Queue that will need worker thread to process
   - This function adds new requests to the queue.  This is done at the per process level. So the queue could grow very quickly and
non-uniformly 
   - The lock ensures multiple processes don’t corrupt the queue while adding updates.  
   - Allows different security groups to be queued dynamically.





#### Method 2: Adaptive solution for batch processing: Dynamic batch intervals to prevent request pile-up AND Batch size limits to ensure AWS requests don’t spike all at once.

This resolves any of the shortcomings of method 1 above which is still prone to API congestion.

The functions basically still work as described in method1 but there are several enhancements to reduce batch API congestion:

MAX_BATCH_SIZE and NUM_WORKERS can be adjusted to accomodate process scaling needs. 

```
import threading
import time

update_queue = []
lock = threading.Lock()
MAX_BATCH_SIZE = 50  # Limits number of requests processed in a single batch
base_interval = 2  # Initial interval, dynamically adjusted

def batch_security_group_updates():
    global base_interval

    while True:
        time.sleep(base_interval)  # Wait before checking the queue

        with lock:
            batch = update_queue[:MAX_BATCH_SIZE]  # Grab at most 50 requests
            update_queue[:] = update_queue[MAX_BATCH_SIZE:]  # Remove processed requests

        start_time = time.time()
        for sg_update in batch:
            try:
                my_ec2.authorize_security_group_ingress(**sg_update)
            except my_ec2.exceptions.ClientError as e:
                if 'InvalidPermission.Duplicate' in str(e):
                    print(f"Rule already exists for {sg_update['GroupId']}")
                else:
                    raise

        elapsed_time = time.time() - start_time
        base_interval = min(5, max(2, elapsed_time * 1.5))  # Dynamically adjust interval

        print(f"Next batch interval set to {base_interval:.2f} seconds")



# Start multiple worker threads
NUM_WORKERS = 4  # Adjust based on expected load
for _ in range(NUM_WORKERS):
    threading.Thread(target=batch_security_group_updates, daemon=True).start()



def queue_security_group_update(GroupId, IpPermissions):
    with lock:
        update_queue.append({'GroupId': GroupId, 'IpPermissions': IpPermissions})


# Example usage:
for sg_id in set(security_group_ids):
    queue_security_group_update(sg_id, [{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }])
```









### General test metrics and test setup for hyper-scaling of processes:

As will be shown, some of the major factors and metrics to monitor are the RAM, swap, CPU, kswapd0, the API contention through the Retry counts in the gitlab pipeline logs. Always ensure that all the instances have successful installations of tomcat9 using a search of "Instalation completed" in the gitlab pipeline console logs.
Also alway make sure to clear the swap on the VPS prior to each test, although testing revealed that this did not impact successive tests when the swap was NOT cleared. Swap can easily be cleared by using this command below in the VPS SSH session:

sudo swapoff -a && sudo swapon -a






### gitlab optimizations:

All of the python testing is done in a pipeline for ease of managment, and quick turnaround and isolation from the main VPS OS.

There have been several things that needed to be optimized with the gitlab docker container that is running the pipeline for the docker container that runs the python code.

The first was that the log capacity had to be increased several times. The per process logging and the console messages for each EC2 instance consumes large amounts of gitlab console logs. This can be increased on a self-hosted gitlab instance like this but not on the public instances. 

The second item was the clearing of the gitlab docker container registry artifacts. Since my gitlab instance is running on a docker container on the VPS use the script below to identify the container id and then docker exec into the container and run the gitlab-ctl registry-garbage-collect periodically. I will incorporate this as a cronjob on the VPS at a later date. The simple shell script is below:

```
[root@vps ~]# cat gitlab_cleanup.sh 
   #!/bin/bash
   CONTAINER_ID=$(docker ps --filter "name=gitlab" --format "{{.ID}}")
   
   if [ -n "$CONTAINER_ID" ]; then
       docker exec -it "$CONTAINER_ID" gitlab-ctl registry-garbage-collect
   else
       echo "No running GitLab container found."
   fi
```





## UPDATES: BENCHMARKING: part 10: main() process and process pooling orchestration level logging infra

This has the main() level logging infra for process level and process pooling orchestration level data.  This is not per process and thread logging. See part 8 below for that.

There are now two main() logging helper functions as shown below.   This was to make the main() process orchestration loggin
more adaptable and extensible in terms of adding new metrics
Per core CPU measurements will need to be added at higher process concurrency levels
All of the other memory based metrics are listed below: RAM, free RAM, and swap usage.  The system has a fixed 16 GB of RAM
The swap has been methodically increased and is now at 16GB in prep for the hyper-scaling
Other enhancements are a radomized inter-test sampling and also some static samplings during test stress (for now at 50% and
75% of a baseline execution time of 10 minutes.
Another enhancement is that the inter-test samples are done with independent but concurrent background threads. The 
multi-threading logic has been pulled out of main() and put into the second helper function below that returns a list
of all the threads to main() . That way the threads can be .join'ed in main() to make sure that the inter-test data is 
completely fetched prior to main(0 flush and cleanup.
Helper function 2 calls helper function 1 for the specific logging semantics that can be used across all of the various 
timing threads. The logging is fully asynchronous so the performance of main() execution code (multi-processing and pooling)
is not affected. This makes the code more performance resilient with the logging overhead.

Helper function 0 is very similar to the process level logging setup_logging() function, except this creates a dedicates
main() log file in the archive directory of the gitlab pipeline as describe below. It is important to call this function early
on in main()



### main() logging helper functions: 

helper function 0:

```
#### ADD the main() level process and process pooling orchestration logging level code. The setup helper function is below
#### The function is incorporated in the main() function
#### This is using the same log_path as used in the per process and threading log level code. /aws_EC2/logs is a mapped
#### volume in the docker container to the project archive directory on the gitlab pipeline repo.  This is the line
#### from .gitlab-ci.yml file:
####     - docker run --rm --env-file .env -v $CI_PROJECT_DIR/logs:/aws_EC2/logs $CI_REGISTRY_IMAGE:latest
#### The logging in main() using this helper function will be logged to the gitlab pipeline console as well as a log file
#### in the archive directory for the pipeline
#### The file will be named /aws_EC2/logs/main_{pid}.log, in the same archive but separate from the process level logs.

def setup_main_logging():
    pid = multiprocessing.current_process().pid
    log_path = f'/aws_EC2/logs/main_{pid}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger("main_logger")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(process)d - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger
```



helper function 1:

```
## (helper logging function) this is for inter-test process orchestration level memory stats.
## What i have done is modularize the threading of these operations into a second function that follows(see below
## this function).
## This function is for the actual logging semantics and output structure
def sample_inter_test_metrics(logger, delay, label):
    """Samples memory and CPU metrics at specific points during execution."""
    time.sleep(delay)  # Wait for the specified timing

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    #cpu_usage = psutil.cpu_percent(interval=None, percpu=True)

    cpu_usage = psutil.cpu_percent(interval=1, percpu=True)

    logger.info(f"[MAIN] {label} Inter-test RAM Usage: {mem.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Free Memory: {mem.available / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test Swap Usage: {swap.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] {label} Inter-test CPU Usage (per-core): {cpu_usage}")

```

helper function 2:


```
## (helper logging function) call this function in the middle of the logging in main() to create the list of independent 
## threads in the background for each thread log timing variant
## The objective is to collect load bearing memory and CPU stats for the hyper-scaling tests
## moving the threading.Thread method outside of main() makes this much more extensible in case I need to add more
## static or dynamic sampling points!!
## NOTE: i forgot to add the thread storage so that we can wait for them to complete in main with .join! It is working now.


def start_inter_test_logging(logger, total_estimated_runtime):
    """Launch separate logging threads and return them for later joining."""
    threads = []  # Store threads for later synchronization

    random_delay = random.uniform(0.3, 0.7) * total_estimated_runtime  # Random 30-70%
    fixed_50_delay = 0.5 * total_estimated_runtime  # Fixed 50%
    fixed_75_delay = 0.75 * total_estimated_runtime  # Fixed 75%

    # Start each thread and store it
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, random_delay, "Random 30/70")))
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, fixed_50_delay, "50%")))
    threads.append(threading.Thread(target=sample_inter_test_metrics, args=(logger, fixed_75_delay, "75%")))

    # Get this list of threads aboe and start them. Grouping them into a list makes this easy to do the .join in
    # main() assuring logging is all complete prior to flush and closing things out in main()
    for thread in threads:
        thread.start()

    return threads  # Return the list of threads to be joined in main()
```



### main() logging changes:

These are the added logging portions to the main() function using the helper functions above. 
This will help at a higher level when we optimize the desired_count relative to RAM VPS usage for hyper-scaling the process number
count. This took several iterations to get to work. The main initial problem was that the execution time portion was not getting 
written to disk and was missing in the main() level log. The fsync stream handler resolved this issue. Other issues were resolved
with the helper functions 1 and 2 above.

The edited out areas of the main() are noted below to save space.


```
def main():
    load_dotenv()


# The helper function setup_main_logging for the logging at the process orchestration level, see below
# Pass this logger into the inter-test helper function call below sample_inter_test_metrics 
    logger = setup_main_logging()


# Define the total_estimated_runtime as global so that it can be used in the call to start_inter_test_logging
# call in main() for the inter-test metrics.  We will use a 0.30-0.70 randomizer and static points on this total_estimated_value 
# in which to take the sample. From previous hyper-scaling of processes 10 minutes is a good baseline for these types of tests.
    global total_estimated_runtime
    total_estimated_runtime = 600  # Adjust based on previous test execution times


<<EDITED OUT>>



### Configurable parameters
    chunk_size = 2     # Number of IPs per process
    max_workers = 2       # Threads per process
    desired_count = 150     # Max concurrent processes

    chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]


    # ADD this for the pooling level logging in main() that uses setup_main_logging() helper function
    total_processes = len(chunks)
    remaining = total_processes - desired_count
    pooled_batches = (remaining + desired_count - 1) // desired_count if remaining > 0 else 0
    # this uses ceiling division. for example 200 processes with desired_count 75 is (125+75-1)//75 =
    # 199/75 = round down(2.65)= 2 additional batches of the 75 max will cover the remaining 125 pooled processes

    logger.info(f"[MAIN] Total processes: {total_processes}")
    logger.info(f"[MAIN] Initial batch (desired_count): {desired_count}")
    logger.info(f"[MAIN] Remaining processes to pool: {remaining}")
    logger.info(f"[MAIN] Number of batches of the pooled processes. This is the *additional waves of processes that will be needed after the initial batch (`desired_count`) to complete all the work: {pooled_batches}")



<<EDITED OUT. The block below ends with the call to the helper function 2 above start_inter_test_logging>>



# The above still not working with execution time in the main log file. Try doing explicit flush and exit
# on the handler, and make sure do execution time log message after multiprocessing pool call and before the flush
# This fixed the issue. 
# Capture memory stats at the start of execution
    logger = logging.getLogger("main_logger")  # Explicitly name it to avoid conflicts
    logger.setLevel(logging.INFO)
    
    initial_mem = psutil.virtual_memory()
    initial_swap = psutil.swap_memory()
    initial_cpu_usage = psutil.cpu_percent(interval=1, percpu=True)  # Capture per-core CPU usage


    logger.info(f"[MAIN] Initial RAM Usage: {initial_mem.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Free Memory: {initial_mem.available / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial Swap Usage: {initial_swap.used / (1024**2):.2f} MB")
    logger.info(f"[MAIN] Initial CPU Usage (per-core): {initial_cpu_usage}")


    logger.info("[MAIN] Starting multiprocessing pool...")


    # Start background logging threads by calling the start_inter_test_logging helper function()
    # I have moved the threading logic outside of main() to make this more extensible and flexible if we need to
    # add more variations in the samples, namely the CPU which is tricky to track and varies quite a bit during 
    # execution. All of these threads are background threads in the main() process
    # This is so that the main() program flow is not interupted in any way.
    # This is an asynchronous design:
    # By starting the inter-test sampling asynchronously, the main multiprocessing workload proceeds uninterrupted, and the 
    # logging thread quietly waits until that thread's retirement interval is reached.
    # Then, in the `finally` block, use a join on the returned list from start_inter_test_logging to make sure all the
    # threaded data has been collected before flush and closing thing out in main()

    inter_test_threads = start_inter_test_logging(logger, total_estimated_runtime)

    start_time = time.time()

    ##### CORE CALL TO THE WORKER THREADS tomcat_worker_wrapper. Wrapped for the process level logging!! ####
    try:
        with multiprocessing.Pool(processes=desired_count) as pool:
            pool.starmap(tomcat_worker_wrapper, args_list)
    finally:
        total_time = time.time() - start_time
        logger.info("[MAIN] All chunks have been processed.")
        logger.info(f"[MAIN] Total execution time for all chunks of chunk_size: {total_time:.2f} seconds")

        # Ensure the inter-test metrics thread that were started in start_inter_test_logging completes before exiting
        # At this point we have the inter-test log information captured!!!
        # Ensure ALL inter-test logging threads assinged to "inter_test_threads" (the list of threads returned from
        # the function, finish before cleanup)
        for thread in inter_test_threads:
            thread.join()


        print("[INFO] All chunks have been processed.")

        # Capture memory stats after execution
        final_mem = psutil.virtual_memory()
        final_swap = psutil.swap_memory()
        final_cpu_usage = psutil.cpu_percent(interval=None, percpu=True)

        logger.info(f"[MAIN] Final RAM Usage: {final_mem.used / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final Free Memory: {final_mem.available / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final Swap Usage: {final_swap.used / (1024**2):.2f} MB")
        logger.info(f"[MAIN] Final CPU Usage (per-core): {final_cpu_usage}")



        # **New Explicit Log Flush Approach**
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler):
                handler.flush()
                handler.stream.flush()  # Ensure OS writes immediately
                os.fsync(handler.stream.fileno())  # Force disk write

        # Now shutdown logging AFTER flushing
        logging.shutdown()

```


The stream handler will forward the logging info to both the gilab pipeline console and the archive directory on the
gitlab pipeline. The main() function will log to its own log file in the artifacts separate from process level log
files by design.
With moderate level number of processes (100-150) this logging is performing welll and I did not notice any added
total execution time for this module.


Example of content saved to the main log file:

Added in Swap, Free RAM memory and RAM usage statistics. These will be the main bottlenecks moving forward with
the process hyperscaling of 200, 300 and 400 processes.  Desired_count adjustments for the number of pooled
processes will be the main way to deal with the memory issues that will be encountered.  The trade off is that
process queue pooling is inherently slower in terms of concurrency and parallelization, but it will be necessary
if RAM is a constant on the VPS controller.

Added inter-test sampling as well as shown below. This has been very helpful in assessing relative performance when 
changing the desired_count.

```
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Total processes: 150
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Initial batch (desired_count): 150
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Remaining processes to pool: 0
2025-05-30 04:18:47,641 - 8 - INFO - [MAIN] Number of batches of the pooled processes. This is the *additional waves of processes that will be needed after the initial batch (`desired_count`) to complete all the work: 0
2025-05-30 04:18:48,643 - 8 - INFO - [MAIN] Initial RAM Usage: 11854.68 MB
2025-05-30 04:18:48,643 - 8 - INFO - [MAIN] Initial Free Memory: 3380.49 MB
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Initial Swap Usage: 0.00 MB
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Initial CPU Usage (per-core): [1.0, 0.0, 1.0, 1.0, 0.0, 0.0]
2025-05-30 04:18:48,644 - 8 - INFO - [MAIN] Starting multiprocessing pool...
2025-05-30 04:22:05,149 - 8 - INFO - [MAIN] Random 30/70 Inter-test RAM Usage: 14277.98 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test Free Memory: 1227.14 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test Swap Usage: 5022.49 MB
2025-05-30 04:22:05,151 - 8 - INFO - [MAIN] Random 30/70 Inter-test CPU Usage (per-core): [8.1, 6.9, 6.1, 5.1, 7.1, 8.0]
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test RAM Usage: 14216.60 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test Free Memory: 1287.11 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test Swap Usage: 5009.99 MB
2025-05-30 04:23:49,645 - 8 - INFO - [MAIN] 50% Inter-test CPU Usage (per-core): [9.3, 9.1, 10.8, 7.1, 8.1, 12.1]
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test RAM Usage: 14165.88 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test Free Memory: 1332.91 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test Swap Usage: 5223.87 MB
2025-05-30 04:26:19,645 - 8 - INFO - [MAIN] 75% Inter-test CPU Usage (per-core): [5.9, 6.1, 4.0, 6.1, 5.9, 4.0]
2025-05-30 04:28:45,264 - 8 - INFO - [MAIN] All chunks have been processed.
2025-05-30 04:28:45,264 - 8 - INFO - [MAIN] Total execution time for all chunks of chunk_size: 596.62 seconds
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final RAM Usage: 8217.49 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final Free Memory: 7279.59 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final Swap Usage: 5256.36 MB
2025-05-30 04:28:45,265 - 8 - INFO - [MAIN] Final CPU Usage (per-core): [13.2, 13.0, 14.2, 13.7, 13.0, 13.0]


```
Early tests are revealing an interesting tradeoff with the increased parallelization of processes when desired_count is
raised up higher and eventually set at max (pooling is turned off). 

With process pooling the swap usage is in general lower due to less concurrency. 

With process pooling turned off (desired_count = total number of processes), the swap usage is 
higher.   

Thus the VPS is under more stress with pooling turned off. 

The downside of running with pooling is that the total execution time is notably slower. 

So moving forward with higher process counts there will have to be a trade off in this fashion and because RAM is affected as
well, at some point the process pooling will be mandatory.

There have been several instances where the VPS freezes up and this is because of VPS contentions issues.

NOTE: it is really important to clear the swap between tests because cleanup is not always complete prior to starting the 
next test. The swap can be cleared on the VPS with: sudo swapoff -a && sudo swapon -a

There was also an interesting issue with CPU core3 on the VPS with process pooling test but not with the test without 
pooling. This will required more testing and investigation. The CPU cores may be differentially affected with pooling vs.
no pooling scenarios.






## UPDATES: BENCHMARKING: part 9: exponential backoff on the authorize_security_group_ingress

Hitting the AWS API limit on the calls to this function with parallel desired_count of 45 on the processes.
Wrap the authorize_security_group_ingress in a wrapper function with exponential backoff retry_with_backoff.
This resolved the 45 desired_count issue and will move up the scaling to higher desired_count on the multi-processing.
The installation time has decreased from 23:50 mintues with desired_count of 30 to 16 mintues with desired_count of 45. Very large improvement.

This error would manifest itself as aborted scripts and failed tomcat9 installations to many of the EC2 instances. This is  no longer happening even at higher scale levels and higher desired_count levels.


The setup consists of 250 EC instances, chunk_size of 2 for 125 processes and max_workers= 2 threads per process.

Two pools are now being created, the one of 45 and then the queued pool of processes of 80

The wrapper function is below:
```
def retry_with_backoff(func, max_retries=5, base_delay=1, max_delay=10, *args, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e):
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0, 1)
                print(f"[Retry {attempt + 1}] RequestLimitExceeded. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                raise
    raise Exception("Max retries exceeded for AWS API call.")
```




The exponential backoff is being used extensively as shown in the gitlab pipeline console logs:

[Retry 1] RequestLimitExceeded. Retrying in 1.86s...
[Retry 1] RequestLimitExceeded. Retrying in 1.82s...
[Retry 1] RequestLimitExceeded. Retrying in 1.04s...
[Retry 1] RequestLimitExceeded. Retrying in 1.53s...
[Retry 1] RequestLimitExceeded. Retrying in 1.87s...
[Retry 1] RequestLimitExceeded. Retrying in 1.97s...
[Retry 1] RequestLimitExceeded. Retrying in 1.67s...
[Retry 1] RequestLimitExceeded. Retrying in 1.89s...


At 70 desired_count, the CPU is getting a bit more taxed, down to 70-80% idle but the pipeline completed wihtout errors 
and all 250 instances are installed with tomcat9
swap is stable as well
The logging infra solid as well as the random sampling of processes in the process group
1 log file per process
Execution time is improving massively:  Record time 12:48 with 70, 23:50 with 30 desired_count and 16:08 with 45 desired count

At 100 desired_count, swap stable at about 5GB of usage.
There is still improvement in exeuction time but diminishing returns:
Record time 12:25 with 100,  12:48 with 70, 23:50 with 30 desired_count and 16:08 with 45 desired count
No missed installations
Logging infra is solid
1 log file per process


At 125 desired_count, this effectively disabled process pooling and it will try to run this without any pooling queue for the processes. The CPU will be taxed more.
In this run the RAM is starting to get high. About 12.9GB used of the 16GB. At hyper-scaling levels of 300 or 400 if this becomes a problem then the pooling will definitely help.   The process pooling entire purpose is for hyper-scaling at these levels.
Record time is 10:24 a large improvement over the 100 desired_count.  Massive improvments over the original setup as well
No missed installations (all 250/250)
Logging infra is solid
1 log file per process
swap is stable at 5 GB.

Execution time summary is below:
desired_count   execution time in minutes:seconds

```
30 → 23:50
45 → 16:08
70 → 12:48
100 → 12:25
125 → 10:24
```


So process pooling for these lower process count levels is slowing the process down and we do not need it.

At the higher hyper-scaling process levels the process pooling will come in useful especially in regards to the 
VPS RAM utilization.





## UPDATES: BENCHMARKING part 8: Multi-processing logging for the pooled/queued processes as well. 

The new code additions are below and will produce logs for the pooled processes as well now:

### Phase 1:
```
## The various models for the per process logging are further down below. With model4 there is still an issue with
## multi-processing pooling whereby the queued processes(pooled) are not getting a log file. This is because of
## process re-use by the multiprocessing pooler. The fix involves:
# Wrap the tomcat_worker and use the wrap function tomcat_worker from the main() call to tomcat_worker as tomcat_worker_wrapper
# - `tomcat_worker_wrapper()` is called **for every task**, even if the process is reused.
# - `setup_logging()` is guaranteed to run at the start of each task, ensuring a fresh log file is created for each process execution.
# - Since using `force=True` in `basicConfig()`, it will override any previous logging config in that process.

def tomcat_worker_wrapper(instance_info, security_group_ids, max_workers):
    setup_logging()  # Ensure logging is reconfigured for each task
    return tomcat_worker(instance_info, security_group_ids, max_workers)
```


```
## and in main()
    # wrap the tomcat_worker in the tomcat_worker_wrapper function (defined at top of file as helper) to fix
    # the problem with the pooled/queued processes not getting their own log file for the multi-processing logging
    # code
    with multiprocessing.Pool(processes=desired_count) as pool:
        pool.starmap(tomcat_worker_wrapper, args_list)
```


### Phase 2:

With this change the log files are now being created but the PID is being reused from the original desired_count set, for the pooled processes. To fix this incorporate the uuid into the name of the log files so that they are no longer overwritting the original process logs with the pooled log that is using the same PID. In this was there will be unique log files for the original process set and all the pooled processes. The updated code is below


```
def setup_logging():
    pid = multiprocessing.current_process().pid
    unique_id = uuid.uuid4().hex[:8]
    log_path = f'/aws_EC2/logs/benchmark_{pid}_{unique_id}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    print(f"[DEBUG] Setting up logging for PID {pid} with unique ID {unique_id} at {log_path}")


    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        #format='%(asctime)s - %(process)d - %(message)s',
        format='%(asctime)s - %(process)d - %(threadName)s - %(message)s',

        force=True  # Python 3.8+ only
```

### Phase 3:

Getting empty log files with the phase 2 changes. Two options: Switch from a basicConfig logger to a stream handler that is ideally
suited for multi-processing and per process logging infrastructure when there is pooling and pid reuse of the processes
This is a complex patch and had some issues.   Option2 is much easier: just remove the second call to setup_logging() in
the tomcat_worker() now that tomcat_worker_wrapper() calls tomcat_worker() and has the setup_logging() call in it (in
the wrapper function). No need to call it twice. Also added thread name to the setup_logging() function as shown above.


The code is now reliably logging 1 log file per process regardless of process type (pooled or non-pooled) and also creates an aggregate log file with all the log files in one file.




## UPDATES: BENCHMARKING part 7: Advanced logging implementation to collect per process CPU, swap memory, etc during the benchmarking tests


The 50 process and 75 process and the 100 process ran fine with the multi-processing pooling and desired_count of 25 (this will be adjusted shortly to optimize). There was no CPU contention or swap memory issues as expected due to the queuing of the test of the processes >25. As expected the time to compelte increased (not linearly).  The 34 process prior took about 8:50 minutes, the 75 process took about 13:20 minutes and the 100 process about 15 minutes.

Next, logging was implemented at the per process level. This involved a lot of code additions, as the setup_logging function needs to be run inside the tomcat_worker prior to running the multi-threading TreadPoolExecutor. There are several functions that are used to accomplish this and the logging is pulled from a mount on the docker container that is running the python script to the mount on the workspace on the gitlab pipeline.   Once this is done the artifacts are pulled into the pipeline and can be easily viewed. The per file process log files are also aggregated into a consolidated file for easy viewing. An example of the per process logging is below:

A key part to getting this to work in multi-processing environment is to use the force below to allow per process logging that is not natively supported in the basic logger.

```
def setup_logging():
    pid = multiprocessing.current_process().pid
    log_path = f'/aws_EC2/logs/benchmark_{pid}.log'
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # Remove any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(process)d - %(message)s',
        force=True  # Python 3.8+ only
    )
```

Sample log output per process is below from the consolidated file:


```
===== logs/benchmark_10.log =====
2025-05-23 21:44:43,694 - 10 - Logging initialized in process.
2025-05-23 21:44:43,694 - 10 - Test log entry to ensure file is created.
2025-05-23 21:44:46,634 - 10 - [PID 10] START: Tomcat Installation Threaded
2025-05-23 21:44:46,635 - 10 - [PID 10] Initial swap usage: 3.51 GB
2025-05-23 21:44:46,635 - 10 - [PID 10] Initial CPU usage: 0.00%
2025-05-23 21:46:48,880 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,892 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,899 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:49,339 - 10 - Authentication (publickey) successful!
2025-05-23 21:46:49,366 - 10 - Authentication (publickey) successful!
2025-05-23 21:46:49,372 - 10 - Authentication (publickey) successful!
2025-05-23 21:47:49,812 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:50,258 - 10 - Authentication (publickey) successful!
2025-05-23 21:53:33,827 - 10 - [PID 10] END: Tomcat Installation Threaded
2025-05-23 21:53:33,827 - 10 - [PID 10] Final swap usage: 3.51 GB
2025-05-23 21:53:33,827 - 10 - [PID 10] Final CPU usage: 0.00%
2025-05-23 21:53:33,827 - 10 - [PID 10] Total runtime: 527.19 seconds
```



```
===== logs/benchmark_11.log =====
2025-05-23 21:44:43,694 - 11 - Logging initialized in process.
2025-05-23 21:44:43,694 - 11 - Test log entry to ensure file is created.
2025-05-23 21:44:46,539 - 11 - [PID 11] START: Tomcat Installation Threaded
2025-05-23 21:44:46,539 - 11 - [PID 11] Initial swap usage: 3.51 GB
2025-05-23 21:44:46,539 - 11 - [PID 11] Initial CPU usage: 0.00%
2025-05-23 21:46:48,658 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:48,673 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:46:49,099 - 11 - Authentication (publickey) successful!
2025-05-23 21:46:49,136 - 11 - Authentication (publickey) successful!
2025-05-23 21:47:49,427 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:49,449 - 11 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 21:47:49,872 - 11 - Authentication (publickey) successful!
2025-05-23 21:47:49,914 - 11 - Authentication (publickey) successful!
2025-05-23 21:53:50,175 - 11 - [PID 11] END: Tomcat Installation Threaded
2025-05-23 21:53:50,175 - 11 - [PID 11] Final swap usage: 3.51 GB
2025-05-23 21:53:50,175 - 11 - [PID 11] Final CPU usage: 0.00%
2025-05-23 21:53:50,175 - 11 - [PID 11] Total runtime: 543.64 seconds
```




This was enhanced with a periodic sampler for CPU and swap memory to the output below (sampling rate of 60 seconds default), but as shown this had a noticable drag on the total runtime of about 50-150 seconds:

```
===== logs/benchmark_10.log =====
2025-05-23 23:53:07,972 - 10 - Logging initialized in process.
2025-05-23 23:53:07,973 - 10 - Test log entry to ensure file is created.
2025-05-23 23:53:10,665 - 10 - [PID 10] START: Tomcat Installation Threaded
2025-05-23 23:53:10,665 - 10 - [PID 10] Initial swap usage: 3.47 GB
2025-05-23 23:53:10,665 - 10 - [PID 10] Initial CPU usage: 0.00%
2025-05-23 23:53:10,670 - 10 - [PID 10] Sampled CPU usage: 0.00%
2025-05-23 23:53:10,670 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:54:10,671 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-23 23:54:10,671 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:54:52,722 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:52,796 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:52,828 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:54:53,550 - 10 - Authentication (publickey) successful!
2025-05-23 23:54:53,678 - 10 - Authentication (publickey) successful!
2025-05-23 23:54:53,825 - 10 - Authentication (publickey) successful!
2025-05-23 23:55:10,671 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-23 23:55:10,671 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:55:53,264 - 10 - Connected (version 2.0, client OpenSSH_8.9p1)
2025-05-23 23:55:53,710 - 10 - Authentication (publickey) successful!
2025-05-23 23:56:10,678 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:56:10,678 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:57:10,679 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-23 23:57:10,679 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:58:10,679 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:58:10,680 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-23 23:59:10,680 - 10 - [PID 10] Sampled CPU usage: 0.30%
2025-05-23 23:59:10,680 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:00:10,681 - 10 - [PID 10] Sampled CPU usage: 0.40%
2025-05-24 00:00:10,681 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:01:10,681 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-24 00:01:10,681 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:02:10,682 - 10 - [PID 10] Sampled CPU usage: 0.20%
2025-05-24 00:02:10,682 - 10 - [PID 10] Sampled swap usage: 3.47 GB
2025-05-24 00:02:59,123 - 10 - [PID 10] END: Tomcat Installation Threaded
2025-05-24 00:02:59,123 - 10 - [PID 10] Final swap usage: 3.47 GB
2025-05-24 00:02:59,123 - 10 - [PID 10] Final CPU usage: 0.00%
2025-05-24 00:02:59,123 - 10 - [PID 10] Total runtime: 588.46 seconds
```



This logging will be used to access performance with the hyper-scaling cases of multi-processing when the desired_count ismehthodically increased.


Model 1: Mult-process logging without sampling

```
@contextmanager
def benchmark(test_name):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    yield

    end_time = time.time()
    end_swap = psutil.swap_memory().used / (1024 ** 3)
    end_cpu = process.cpu_percent(interval=1)

    logging.info(f"[PID {pid}] END: {test_name}")
    logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
    logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
    logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

def run_test(test_name, func, *args, **kwargs):
    with benchmark(test_name):
        func(*args, **kwargs)
```







Model 2: Multi-process logging with the basic sample code determinisic with fixed interval. 
This produced a drag on completion time for all of the processes due to sample collisions between the processes
Writing to a shared mount (docker mount to gitlab workspace) also made the issue worse.
The sampler code is shown below:


```
def sample_metrics(stop_event, pid, interval):
    process = psutil.Process()
    while not stop_event.is_set():
        cpu = process.cpu_percent(interval=None)
        swap = psutil.swap_memory().used / (1024 ** 3)
        logging.info(f"[PID {pid}] Sampled CPU usage: {cpu:.2f}%")
        logging.info(f"[PID {pid}] Sampled swap usage: {swap:.2f} GB")
        stop_event.wait(interval)
@contextmanager
def benchmark(test_name, sample_interval=60):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    stop_event = threading.Event()
    sampler_thread = threading.Thread(target=sample_metrics, args=(stop_event, pid, sample_interval))
    sampler_thread.start()

    try:
        yield
    finally:
       stop_event.set()
        sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)

        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

# set the sample_interval here. Default is 60 seconds
def run_test(test_name, func, *args, sample_interval=60, **kwargs):
    with benchmark(test_name, sample_interval=sample_interval):
        func(*args, **kwargs)
```





Model 3 of the sampler: randomize a period of 50 to 250 seconds in which to take a single sample per process. This will minimize the probability of sample collisions that were slowing down the runtime of the tests.  The modified code is below:
This still had poor performance. 

```
import random
def sample_metrics_once_after_random_delay(pid, delay):
    time.sleep(delay)
    process = psutil.Process()
    cpu = process.cpu_percent(interval=None)
    swap = psutil.swap_memory().used / (1024 ** 3)
    logging.info(f"[PID {pid}] Random-sample CPU usage: {cpu:.2f}% after {delay:.1f}s")
    logging.info(f"[PID {pid}] Random-sample swap usage: {swap:.2f} GB")

@contextmanager
def benchmark(test_name, sample_delay):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    sampler_thread = threading.Thread(
        target=sample_metrics_once_after_random_delay,
        args=(pid, sample_delay)
    )
    sampler_thread.start()

    try:
        yield
   finally:
        sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)

        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")

        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, **kwargs):
    delay = random.uniform(min_sample_delay, max_sample_delay)
    with benchmark(test_name, sample_delay=delay):
        func(*args, **kwargs)
```


Model 4 of the sampler: Combine the randomizer with a randomizer on the processes to sample (10% sample over time)
This appears to have resolved the sampling contention and will be used for the process hyper-scaling.

Randomize the process in which to sample and also randomize when that random sample is taken during the execution time. This minimizes logging contention when processes are massivvely scaled and has been tested for such.

The benefits are:

Selective sampling: Only a random 10% of processes log detailed metrics, which avoids overwhelming the disk and CPU.

The 10% probability is configurable

Randomized delay: Prevents log spikes and contention by staggering when metrics are collected.

The randomized delay interval is also configurable. It is based upon typical large scale process execution times for this particular python module

Thread-safe sampling: The sampler runs in a separate thread and joins cleanly, ensuring no orphaned threads.

Context-managed benchmarking: Clean start/end logging with CPU and swap usage, wrapped around any function.


Here is the revised code:

```
def sample_metrics_once_after_random_delay(pid, delay):
    time.sleep(delay)
    process = psutil.Process()
    cpu = process.cpu_percent(interval=None)
    swap = psutil.swap_memory().used / (1024 ** 3)
    logging.info(f"[PID {pid}] Random-sample CPU usage: {cpu:.2f}% after {delay:.1f}s")
    logging.info(f"[PID {pid}] Random-sample swap usage: {swap:.2f} GB")

@contextmanager
def benchmark(test_name, sample_delay=None):
    process = psutil.Process()
    start_time = time.time()
    start_swap = psutil.swap_memory().used / (1024 ** 3)
    start_cpu = process.cpu_percent(interval=1)

    pid = multiprocessing.current_process().pid
    logging.info(f"[PID {pid}] START: {test_name}")
    logging.info(f"[PID {pid}] Initial swap usage: {start_swap:.2f} GB")
    logging.info(f"[PID {pid}] Initial CPU usage: {start_cpu:.2f}%")

    sampler_thread = None
    if sample_delay is not None:
        sampler_thread = threading.Thread(
            target=sample_metrics_once_after_random_delay,
            args=(pid, sample_delay)
        )
        sampler_thread.start()

    try:
        yield
    finally:
        if sampler_thread:
            sampler_thread.join()

        end_time = time.time()
        end_swap = psutil.swap_memory().used / (1024 ** 3)
        end_cpu = process.cpu_percent(interval=1)
        logging.info(f"[PID {pid}] END: {test_name}")
        logging.info(f"[PID {pid}] Final swap usage: {end_swap:.2f} GB")
        logging.info(f"[PID {pid}] Final CPU usage: {end_cpu:.2f}%")
        logging.info(f"[PID {pid}] Total runtime: {end_time - start_time:.2f} seconds\n")

def run_test(test_name, func, *args, min_sample_delay=50, max_sample_delay=250, sample_probability=0.1, **kwargs):
    delay = None
    if random.random() < sample_probability:
        delay = random.uniform(min_sample_delay, max_sample_delay)

    with benchmark(test_name, sample_delay=delay):
        func(*args, **kwargs)
```



## UPDATES: BENCHMARKING part 6: testing the multi-processing hyper-scaling with the pooling code

Initial tests look very good. The problematic process count > 25 where there were installation failures is not occuring withe process pooling. 

Tested 200 instances with chunk_size of 6 for 34 processes and it went well.
Swap was almost exhausted at nearly 4GB so increase swap to 8 GB for futher testing below.
This test took longer than the baseline non-pooled of 6:30 minutes at about 8:50 minutes but that is expected as there are 9 processes in the queue that need to wait to be processed over the desired_count limit of 25

The CPU was fairly stable at an average of 70% on the VPS controller. 

Planned further testing:
Using a chunk_size of 4 and max_workers of 4 run the following tests

- 200 instances → 50 processes
- 300 → 75
- 400 → 100

Decrease chunk_size to 2 and run the following test:
- 250 → 125
- 300 → 150
- 400 → 200

Note use the t2.small since the AWS limit is at 402 vCPUs


There are a variety of things that will be monitored dudring these test on the VPS and they will be added to this README as the testing progresses.

The code is all checked in at this time for this module2.






## UPDATES: BENCHMARKING part5: 

Sanity testing of 200 and 400 instances

200 instances with 10 chunk size and 10 threads for 20 processes ran fine. All instances have tomcat installed. So the issue is clearly with the number of processes < 25 and not number of instances, or SSH connections, etc.

400 instances with 20 chunk and 20 threads also running. Had to increase gitlab runner log capacity from 10 MB to 50 MB. TThis worked as well confirming that it is the  number of processes and nothing else. 

The increase in swap from 1GB to 4GB will help the VPS when scaling to 100+ processes as the python code is refactored to support this hyper-scaling corner case.


### Code refactoring to deal with the process hyper-scaling issue > 25:

1. Introduce a process pool or task queue model
2. Add centralized logging and error handling
3. Ensure failed installations are always reported. Currently the Installation succeeded on is working but the Installation failed is falling through, and it is not catching when the process overload causes failed tomcat9 installations on some of the instances
4. Optionally add a post-run audit summary


REFACTORED main() to support multi-processing with pooling to deal with hyperscaling case
 note that this is still based upon Model 2 from the original main() below that does not have the pooling with
 the multiprocessing

 with model 2: each process handles chunk_size of IPs with max_workers number of threads. Any extra IPs use
 an additional process.

 This main() uses the tomcat_worker rather than the original install_tomcat_on_instances used in the main() 
 without pooling.   The tomcat_worker permits pickling by main().   

 The pooling will start the desired_count of concurrent processes (25 has been tested for error free)
 The rest of the processes will be initiated as the original 25 finish up their tasks and exit, one by one
 with multiprocessing.Pool(processes=desired_count) as pool:
 from extensive testing it is recommended to keep desired_count to 25 for this pariticular setup

 The chunk_size is the number of IPs (dictionary list) assigned per process

 max_workers is the number of threads in the ThreadPoolExecutor to use to parallel process the SSH connections for
 the chunk dictionary list of IPs.  

 chunk_size should always be less than or equal to max_workers. If oversubscribing max_workers performance degrades
 very raplidly.  Unused threads (undersubscrbing, with chunk_size < max_workers) does not degrade performance.

 chunk is the actual dictionary list of IPs to be processed per process

 chunks is the dictionary list of all of the IPs to be processed (the total len(instance_ips) of IPs)
 chunks = [instance_ips[i:i + chunk_size] for i in range(0, len(instance_ips), chunk_size)]
 chunks is required to track the entire list of all the IPs because the desired_count cannot process them all
 in parallel initially and has to take up the extras serially as the pool of processes free up, one by one.

 args_list is the List of args_list = [(chunk, security_group_ids, max_workers) for chunk in chunks]  passed to the tomcat_worker function above
 using the pool.starmap pool.starmap(tomcat_worker, args_list) to assign the chunk blocks to each successive
 process running in parallel (initially the desired_count of processes)

 the configurable options are chunk_size, max_workers (like with model2) and desired_count
 The total number of EC2 instances are specified in the .gitlab-ci.yml and passed and env variables to the first
 python module in the python package for this project (11 modules so far)




## UPDATES:  BENCHMARKING part4: Hyperscaling the multi-processing


T3.small 200 instances with 200 processes and 1 thread per process (chunk_size =1)
At 200 the VPS got a bit stuck at around 137 but then proceeded to slowly create the rest of the processes.
So there is a bit o bottleneck hit here. We did not see this with 149 process test.  
I did see the VPS controller CPU go to 0 idle periodically so it was maxed out for short periods.

Once the processes were up and running thing proceeded as expected.
I did a quick spot check on AWS and all 200 instances have status up and checks are ok. And the python script did well screening for this.
Amazingly the entire script completed in about 7 minutes, just a bit longer than usual. This slight deviation is due to the process bring up being a bit slow once getting above 150 processes. 



T2.small 400 instances with 400 processes and 1 thread per process (chunk_size=1)

Change to t2.small. This might affect the control of the testing as these are slower to come up and the installation could be slower with 1 vCPU, but the focus is on the 400 processes and the mutli-processing with no multi-threading in each process (1 thread per process).
Have to switch to t2.small because AWS limit currently at 402 vCPUs and t3.small have 2 vCPU per instance.

This test hit a bottleneck with the VPS. CPU gets tapped out. The gitlab container is running a docker container that is runing the python master script.  The top shows the contention and the idle CPU drops to 0


```
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R 100.0   0.0  25:23.80 kswapd0                                            
1998254 root      20   0 1139656  10832   2128 S  41.5   0.1   3:50.24 fail2ban-server                                    
2005387 1001      20   0 1238948   9132   1196 S  28.9   0.1   0:47.86 go-camo    




    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R  72.1   0.0  25:32.10 kswapd0                                            
    456 root      20   0 2241208  13612   1652 S  23.4   0.1  28:28.77 containerd                                         
2616745 112       20   0  122344  79376   1396 D  21.4   0.5   0:01.59 amavisd-new                                        
   1302 root      20   0 3693788  34924   1900 S  18.8   0.2 210:26.35 dockerd   
```

Once this occurs the gitlab container also running on the VPS locks up.   Putting the gitlab container on a separate VPS would be a solution part of this problem.

### multi-processing issues:

With the testing above it revealed another issue. With processes greater than 25 there appears to be an issue with all of the EC2 instances getting tomcat9 actually installed. This is most likely caused by one or several of the issues below and we need to refine the python script using a variety of techniques to accomodate such edge cases.

Some of the causes might be due to:
VPS (6 vCPUs) + Docker + GitLab runner setup likely hits a resource ceiling when too many processes are spawned simultaneously. This causes:

- Process crashes or hangs
- Silent failures
- Incomplete logging


Stated more concisely:

  - Process management overhead
  - Docker or GitLab runner limits
  - Lack of proper inter-process error handling or logging

The silent failures and process crashes would not necessarily be caught by the curent code failure detection.


### Possible solutions that will be explored: 

To resolve this will have to try some of the folowing or all of the following approaches:
(these all effectively try to control the process concurrency since the problem cannot be resolved directly without 
changing the hardware, docker container distribution, etc.


1. Dynamic Process Scaling
   → Adjusts the number of processes based on system load or available CPUs  
   Prevents overload while still maximizing throughput

2. Process Pooling
   → Reuses a fixed number of worker processes  
   Lets you queue up 100+ tasks but only run, say, 25 at a time

3. Centralized Logging & Error Handling
   → Ensures no failures go unnoticed  
   Helps you detect and retry failed tasks

4. Task Queue Model (e.g., `multiprocessing.Queue` or `concurrent.futures`)  
   → Submit all 100+ tasks, but only a safe number run concurrently  
   Scales to hundreds of tasks without overwhelming the system



### production level soultions in real world would avoid this situation by properly configuring threads per process and chunk_size, etc....


- Increase `chunk_size` to reduce the number of processes
- Stay within the known-safe range (e.g., ≤25 processes)
- Scale horizontally if needed (e.g., split the workload across multiple VPS containers or runners)








## UPDATES: BENCHMARKING part 3:

After the extensive benchmark testing we can see the benefits of multi-processing and multi-threading.
Due to the VPS archlinux and docker effective use of multi-processing, there is no detriment when using a variety of
different chunk_sizes and thread counts. The key is that the chunk_size must be kept equal to or below the max_workers, i.e. the nubmer of threads 
(under provisioning the ThreadPoolExecutor has no determental cost).  As long as that is done, the number of processes can be increased up to 
149 processes with 1 thread per process for the high scale case (149 EC2 instances) or it can be spread out amongst a much
smaller number of processes (13) (for example chunk_size of 12 for 13 processes) or something in the middle with 
chunk_size of 2, for example for 75 processes. All of these permutations yield approximately the same completion time.
At this state, the bottleneck is the I/O time of the SSH connections and the installation time on each instance.
One other bottleneck is the type of EC2 instance. Moving from t2.micro to t3.small improved the time to Status ready
so that the SSH connections could be initiated sooner in the process.   imagine t3.large would improve the time even further in this respect. The installation time would also improve as well the larger the EC2 type.


Without any type of parallelism, i.e. removing the ThreadPoolExecutor and setting the chunk_size to 149 for one process, will show the effects of no parallelism at all. 
In this case, the test was going so slow I had to abort it as it would take hours.
This is compared to the roughtly 6:30 minutes for the parallelized versions that are provisioned correctly.
After aborting test, by the logs it looked like about 1 instance per minute, so 149 instances would have taken about 2.5 hours.

The final test is keeping the chunk_size at 149 for one process but adding back the multi-threading and max_workers of
149 for 149 threads.  Comment back in the ThreadPoolExecutor.  This will illustrate the multi-threading performance alone.This was at 6:50 minutes, closely aligned to the other optimized performances.

Conclusions: 

Multithreading alone is just as effective as multiprocessing for this I/O-bound workload — as long as thread provisioning is correct.

The real performance gain comes from concurrency, not from the specific mechanism (threads vs. processes).

The system (6 vCPU core VPS + Docker + Linux scheduler) handles both models efficiently. 

Also of note this scales well. There is no significant difference between 100 instance case and the 149 instance case as long as the chunk_size and number of threads are provisioned correctly for optimal processing (keep the chunk_size less than or equal to the number of threads).




## UPDATES: BENCHMARKING part 2: Scaling issues to EC2 instances > 100

Had to modify the python describe_instance_status as the DescribeInstanceStatus method overloaded for > 100 instances.

Create a helper function and batch process the EC2 instances so that this method can consume them properly

Helper function:

```
def describe_instances_in_batches(ec2_client, instance_ids):
    all_statuses = []
    for i in range(0, len(instance_ids), 100):
        batch = instance_ids[i:i + 100]
        response = ec2_client.describe_instance_status(InstanceIds=batch, IncludeAllInstances=True)
        all_statuses.extend(response['InstanceStatuses'])
    return all_statuses
```


Next issue is the gitlab-runner logs hit max at 4MB. Since this is a self-hosted runner, edit the /etc/gitlab-runner/config.toml with the following addition. NOTE the placement must be at the line below. it will not work otherwise. Restart the gitlab-runner as well.


```
[[runners]]
  name = "vps.****************.com"
  url = "https://**************.com"
  id = 1
  token = "***************************"
  token_obtained_at = 2024-10-09T21:19:49Z
  token_expires_at = 0001-01-01T00:00:00Z
  executor = "shell"
  output_limit = 10240 <<<<<<<<<<<< THIS MUST BE PLACED HERE and not further down.
  [runners.custom_build_dir]
  [runners.cache]
    MaxUploadedArchiveSize = 0
    [runners.cache.s3]
    [runners.cache.gcs]
    [runners.cache.azure]
```

The benchmarking consistes of a 12 thread 12 chunk_size for 13 process test compared to
2 thread 2 chunk_size and 75 process test to assess the effect of number of processes in the python multi-process
master file.

There does not appear to be any drag on the completion time with the 75 processes. The VPS CPU is ok during this as well.
The processes are run in a docker container and I did not see the docker daemon remarkable stressed during the pipeline run.




## UPDATES: BENCHMARKING part1: Summary of benchmark findings for module 2 (mutli-processing and multi-threading)



The key variables are num_processes, chunk_size and max_workers (number of threads). Some general early findings are listed below:

I ran a lot of benchmark tests. The number of processes is always adjusted to accommodate the chunk_size so the number of processes does not come into play.  I even ran model 3 which adds dummy processes and they don't appear to slow things down in terms of strict process overhead.      The key is the chunk_size relative to the the max_workers (number of threads). If the chunk_size is greater than the  number of threads the performance gets much worse (about 6.5 mintues vs. 9.5 minutes)     If the number of threads is equal to the chunk_size the performance is better. It does not improve or get worse if chunk size is reduced less than the number of threads (in other words the idle threads don't have a determinantal effect on overall time).  

If i increase the chunk size way over the thread count the performance is very poor and gets worse the more the oversubscription to the ThreadPoolExecutor. So good design definitely means that the chunk_size should be less than or equal to the max_workers (number of threads).  The performance suffers in line with how oversubscribed the thread pool executor is. For example with chunk size 8 and threads 6 it is at 8 minutes (6:30 minutes is the time it takes when thread pool executor is not oversubscribed and it is provisioned correctly). I then tried chunk size of 24 and threads 6 and it took 14:45 minutes! So much worse.  I did chunk_size of 12 and threads 6 and as expected is was in the middle of these at 9:30 minutes.    I then ran chunk size of 6 and threads 6 and  it was at what i refer to as the "normalized" time of 6:25. About 6.5 minutes seems to be the optimal time in terms of chunk size and thread provisioning.   

There might be some further optimizations that we can do with the number of processes for my 6 core VPS system, but i haven't seen any obvious advantages of restricting the number of processes to the number of cores(6) but this needs more examination and testing.  At a high level as long as the chunk size relative to thread count is provisioned correctly, I don't see any large differences in the different number of processes across these correctly provisioned cases (i.e, they all finish up in about 6.5 minutes)                Also as expected running a 12 thread with 24 chunk size, the time is better than the 6 thread and 24 chunk size, for example, as expected. (Even though both of these are not provisioned optimally). So the more oversubscription of the ThreadPoolExecutor the worse the performance. This aligns with more context switching as the oversubscription gets worse, causing worsening performance, and dramatically so.    

Another note. I ran tests with low number of threads (4) just to see if degree of oversubscription made a difference and from what I can tell it does. Comparing the results to the 6 thread case for the same chunk sizes, the 4 thread times are worse.

These times below for oversubscription are extremely bad because thread is so low at 4. Comparisons to thread 6 case are listed below as well and as expected they are a better than the tread 4 case, but still very suboptimal.



Chunk size 12 and threads  4
9 processes
Moderately oversubscribed
I see the 4 ip block process finish quite early since threads 4 is sufficient to process these ips quickly. It is the oversubscribed processes that lag a long time.(the other 8 processes)
12:09
Vs. 9:39 with 6 threads so it gets worse in expected fashion


Chunk size 8 and threads 4
13 processes
Lightly oversubscribed
9:30
Vs. 8 minutes with 6 threads. So it gets worse in expected fashion


Chunk size 24 and threads 4
5 processes
substantially subscribed
20:18
Vs. 14:45 with 6 threads. So it gets worse in expected fashion


Chunk size 4 and threads 4
25 processes
Correctly provisioned
(Expect this to be around 6:30)
6:50 so this is line with the expectation.

About the multi-processing dynamics:
Note when comparing this to the 6 thread and 6 chunk size case, with 17 processes there is very little difference. Both are correctly provisioned for chunk_size relative to number of threads per process which controls this test to baseline.
The process overhead (increase from 17 processes to 25 processes) does not seem to adversely affect the performance as long as the processes are not massively over provisioned is my conclusion (need to verify a massive overprovision with perhaps 200 EC2 instances and chunk_size of 2 for 100 processes).  With 6 VCPU cores, we are not constrained to 6 process optimal state.   I have not determined an optimal number of processes yet.

Another note with the test like this with chunk size equal to threads, is that I can observe the multi-processing at work very well.
Very roughly speaking all of the processes wrap up processing in about the last minute of the test run.   So they all start completing roughly in the same time frame. The archlinux VPS OS is doing a pretty good job distributing the threads in the processes over the 6 vCPU cores from what I can see. Otherwise we would see a large disparity in the completion times of the processes for their respective ip blocks.






## UPDATES:

further testing with multi-threading and multi-processing for tomcat installation module 2.
There are now 3 different models to test with this.   Increase EC2 to t3.small as that was a bottleneck as well.
These models provide testing flexibility and decouple the chunk_size from mum_processes (Models 2 and 3)

The max_workers for the ThreadPoolExecutor is defined separately and in an earlier code block. This is the number of threads per process

num_processes value is specified separately

The 3 models are below



Model 1:

Model 1: Fixed Number of Processes num_processes.  Chunk size is dynamic based upon the num_processes and number of ips. In the default case 50 Ips and 8 num_processes will use a chunk_size of 6 and remainder 2 in last process.  This has the new wait_for_public_ips code (see Mddel 2 for more detail on this), so the delay is no longer fixed but dynamic.  main() calls install_tomcat_on_instances for all three models so the multi-threading is done by ThreadPoolExecutor for all three models.  main() calls wait_for_public_ips prior to install_tomcat_on_instances so that we can be sure that public ips are present on all Ips in the the test pool.

- Number of processes is fixed (`num_processes`).
- Each process gets a chunk of IPs.
- The last process handles any remainder.
- Controlled parallelism, predictable resource usage.

```
    chunk_size = len(instance_ips) // num_processes
    processes = []

    for i in range(num_processes):
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
        if i == num_processes - 1:  # Add remaining instances to the last chunk
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
```


Model 2: (REMAINDER METHOD: don't use this)


```
chunk_size = 12
processes = []

>> Calculate how many full chunks we actually need
num_chunks = len(instance_ips) // chunk_size
remainder = len(instance_ips) % chunk_size

for i in range(num_chunks):
    chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
    
    >> If this is the last used chunk, add the remaining IPs
    if i == num_chunks - 1 and remainder > 0:
        chunk += instance_ips[(i + 1) * chunk_size:]

    process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    processes.append(process)
    process.start()

for process in processes:
    process.join()
```


Model 2:  (CEILING DIVISION METHOD: this is cleaner but does involve adding one additional process to deal with the
extra overflow of ips from chunk_size)

Model 2 (Revised): Fixed Chunk Size, Dynamic Process Count

- You define `chunk_size`, and the number of processes is calculated.
- Uses ceiling division to avoid remainder logic.
- Good for: Load balancing when you care more about chunk size than number of processes.
Using ceiling division, an additional process will be added to process the remaining IPs, rather than adding them to the
last process (model1)
Note new code is in here wait_for_public_ips so that there are no orphan EC2 instances that are not included in the last process.  The code is no longer fixed delay wait time but dynamic based upon a loop to check the public_ips on the instances, with exponential backoff algorithm for efficiency.

```
chunk_size = 12
processes = []

# Debugging instance_ips
print("[DEBUG] instance_ips is defined:", 'instance_ips' in locals())
print("[DEBUG] instance_ips length:", len(instance_ips) if 'instance_ips' in locals() else 'N/A')

# Calculate how many chunks we need (ceiling division)
num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size

for i in range(num_chunks):
    start = i * chunk_size
    end = min(start + chunk_size, len(instance_ips))  # safely cap the end index
    chunk = instance_ips[start:end]

    process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    processes.append(process)
    process.start()

for process in processes:
    process.join()


```


Model 3: REMAINDER METHOD (don't use this)

```
chunk_size = 12
processes = []

>> Calculate how many full chunks we need
num_chunks = len(instance_ips) // chunk_size
remainder = len(instance_ips) % chunk_size


for i in range(num_processes):
    if i < num_chunks:
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        if i == num_chunks - 1 and remainder > 0:
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    else:
        # Dummy process that just logs it's unused
        process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))
    
    processes.append(process)
    process.start()


```




Model 3: CEILING DIVISION METHOD

Model 3 (Revised): Fixed Number of Processes, May Be Underutilized

- Always spawns `num_processes`, even if some are unused.
- Useful for testing or simulating a fixed pool of workers.
- Good for: Benchmarking or stress testing process overhead.
This is the same as Model2 except that the num_processes is always spawned regardless if they are required to process the number if IPs. . This uses the new wait_for_public_ips function as well.



```
chunk_size = 12
processes = []

# Calculate how many chunks we need (ceiling division)
num_chunks = (len(instance_ips) + chunk_size - 1) // chunk_size

for i in range(num_processes):
    if i < num_chunks:
        start = i * chunk_size
        end = min(start + chunk_size, len(instance_ips))
        chunk = instance_ips[start:end]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))
    else:
        # Dummy process that just logs it's unused
        process = multiprocessing.Process(target=lambda: print(f"Process {i} not used"))

    processes.append(process)
    process.start()

for process in processes:
    process.join()

```

## UPDATES:

Did extensive testing of the multi-processing vs. multi-threading environment for the master python file and also introduced the module 2 optimizations for the install tomcat module (with multi-processing and limit the multi-threading in the ThredPoolExecutor to 6, the number of VCPU cores on the VPS.

For the first set of tests determined that the multi-processing for the master python execution of the 11 modules is  bit faster than the muti-threaded version.  

Next testing is with the module 2 testing. First try without multi-processing within the module 2 (no main() calling function of the original function).   The original function does not use multi-processing (6 processes) to distribute the ThreadPoolExecutor SSH threading connections over all cores. This took about 10 minutes
This just starts the 50 threads across all of the 6 VCPU cores in a random fashion and could cause context switching issues and contention.

The modules 1 and 2 took 10:13




Next do the 6 processes and 6 threads for each process in the ThreadPoolExecutor
Modules 1 and 2 took 11:50

Next do 8 processes and 12 threads for each process in the ThreadPoolExecutor
Modules 1 and 2 took 9:37








## UPDATES:

Major overhaul of the second module for installation of tomcat onto each of the 50 EC2 instances that are placed in the ALB target group. This was running ok with the ThreadPoolExecutor but inefficently as there were 50 threads randomly executed across the 6 cores causing contention and a lot of context switching. New approach is running in the master script that is running multi-processing. Then the changes were made to the second module that installs tomcat on each of the 50 EC2 instances.   This involved adding a main() function to the module that wraps around the original install module.   The main() functino institutes multi-processing.   First 6 processes are started because the VPS is 6 core CPU. . Each process then invokes the original tomcat function that was modified to only run 6 threads per function call instead of 50 threads like before. So each process in main() calls the install tomcat function which runs 6 threads to consume the block of ip addresses allocated to each process.

The chunk ip allocation block of ips is in the main() function below and is detailed below.  For example with 50 IP addresses and 6 processes there is an 8 block of ips assigned to each process. Because there is an extra 2 IPs there is math logic in the chunk code to assign the remaining IPs (in this case 2) to the last process an the last process will consume them.(10 ip addresses in this case).

Further detail in install_tomcat_on_instances original function:


```
### HERE IS THE MAIN CHANGE FOR THE multiprocessing optmization. First we are going to tie the thread pools
    to the number of cores (the VPS has 6 CPU cores).  Each ThreadPoolExecutor will have max workers of 6 at a time.
    Previously we had max_workers set to length of public_ips which is 50. This is creating a lot of contention with only
    6 cores and a lot of context switching.    To optimize this first we will restrict this to the os.cpu_count of 6
    This means that there will be 6 threads at the same time. To further optimize this with main() function below, we 
    will also start 6 processes defined by num_processes=os.cpu.count (6 as well.  Each process wil invoke the 
    install_tomcat_on_instances function running the 6 ThreadPoolExecutor threads on its dedicated core.   Thus there
    are on average 6 threads running on a process on each of the 6 cores, for 36 concurrent SSH tomcat installations
    at any time. This will reduce the contention of just running ThreadPoolExecutor with all 50 threads randomly assigned
    across the cores which created a lot of context switching. NOTE that chunk size is another variable. See main() below
    Chunk size is the chunk of ips that are grabbed by each process. So if 50 ip addresses each of the 6 processes will
    get 8 ip addresses, and each process can use the 6 threads in the process to process the SSH connections.  In this
    case 6 ips processed immediately and then the other 2 when some of the 6 threads are done with the initial 6 ips.
    however need additionl logic because with 50 instances and 6 processes there are 2 "orphaned" ips that need to be
    dealt with. This requires additional logic.

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(install_tomcat, ip['PublicIpAddress'], ip['PrivateIpAddress'], ip['InstanceId']) for ip in instance_ips]
```




Further detail in main():

```
### Use multi-processing to distribute SSH connections across multiple cores
    num_processes = os.cpu_count()
    
      the chunk_size is determined by number of instances divided by num_processes. num_processes is 6 and 
     number of instances is 50 so 50/6 = 8. The division is // for an integer with floor division
     this chunk size is then used to calculate the block of ips to pass to install_tomcat_on_instances (see below)
     for each process iteration i= 0 to num_processes-1 or 0 to 5 for processes 1 through 6
     Each process is assigned a block of 8 with the last 2 leftovers assigned to the last chunk which is assigned 
     to the last process #6. So the last process will get 10 ips to process. 
     As noted above the processes utlize install_tomcat_on_instances which runs ThreadPoolExecutor of 6 threads to
     process the assigned ip block.  So 6 ips handled immediately and the other 2 when any other thread frees up
     This minimizes contention and context switching.
    
    chunk_size = len(instance_ips) // num_processes
    processes = []

    for i in range(num_processes):
        chunk = instance_ips[i * chunk_size:(i + 1) * chunk_size]
        #process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk,))
        if i == num_processes - 1:  # Add remaining instances to the last chunk
            chunk += instance_ips[(i + 1) * chunk_size:]
        process = multiprocessing.Process(target=install_tomcat_on_instances, args=(chunk, security_group_ids))    
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
```




## UPDATES:

Running on 11 modules in multi-processing master script. This is running fine. This is using the function approach as well from the master script. Running on 6 processes because the VPS has 6 cores.


## UPDATES:

Now running all 11 modules in multi-threaded environment, with each of 11 modules running as a dedicated thread and grouping several of them for concurrency to speed up the infra rollout. The execu function call in the master python script ended up causing many scope related issues in the first 6 modules. I converted the entire script to a function call based multi-threading and wrapped all the python files in the package directory in dedicated function that is called from the master. The master python script is below for reference.   This runs very well all the way through without any scope related issues.

commit:
    major overhaul of multithreaded set up for all 11 modules. The first 6 modules had several scope related issues and so converted the master python script use function calls to the modules rather than exec function which has scoping issues. Had to wrap all modules in their respective function call names. Referring to them by path name rather than module object name but either approach is fine


The thread that takes the longest, the installation of tomcat on each of the 50 EC2 instances cannot be parallelized with any of the other treads because the EC2 instances are in the target group and tomcat has to be running so that the ALB passes target health checks when the ALB is created.

```
def run_module(module_script_path):
    logging.critical(f"Starting module script: {module_script_path}")
    with open(module_script_path) as f:
        code = f.read()
    exec(code, globals())
    logging.critical(f"Completed module script: {module_script_path}")

def restart_ec_multiple_instances():
    run_module("/aws_EC2/sequential_master_modules/restart_the_EC_multiple_instances_with_client_method_DEBUG.py")

def install_tomcat_on_instances():
    run_module("/aws_EC2/sequential_master_modules/install_tomcat_on_each_of_new_instances_ThreadPoolExecutor_list_failed_installation_ips_3.py")

def save_instance_ids_and_security_group_ids():
    run_module("/aws_EC2/sequential_master_modules/save_instance_ids_and_security_group_ids_to_json_file.py")

def create_application_load_balancer():
    run_module("/aws_EC2/sequential_master_modules/create_application_load_balancer_for_EC2_tomcat9_instances_json_pretty_format_BY_ALB_NAME.py")

def ssl_listener_with_route53():
    run_module("/aws_EC2/sequential_master_modules/SSL_listener_with_Route53_for_ACM_validation_with_CNAME_automated_3_BY_ALB_NAME.py")

def wget_debug():
    run_module("/aws_EC2/sequential_master_modules/wget_debug4.py")

def elastic_beanstalk():
    run_module("/aws_EC2/sequential_master_modules/Elastic_Beanstalk_ORIGINAL_with_environment_id_WORKING_VERSION_BY_ElasticLB_env_id_without_RDS.py")

def rds_and_security_group():
    run_module("/aws_EC2/sequential_master_modules/RDS_and_security_group_json.py")

def jumphost_for_rds_mysql_client():
    run_module("/aws_EC2/sequential_master_modules/jumphost_for_RDS_mysql_client_NEW3.py")

def wget_for_elastic_beanstalk_alb():
    run_module("/aws_EC2/sequential_master_modules/wget_for_elastic_beanstalk_ALB.py")

def https_wget_for_elastic_beanstalk_alb():
    run_module("/aws_EC2/sequential_master_modules/HTTPS_wget_for_elastic_beanstalk_ALB.py")

def main():
    thread1 = threading.Thread(target=restart_ec_multiple_instances)
    thread1.start()
    thread1.join()

    thread2 = threading.Thread(target=install_tomcat_on_instances)
    thread2.start()
    thread2.join()

    thread3 = threading.Thread(target=save_instance_ids_and_security_group_ids)
    thread3.start()
    thread3.join()

    thread4 = threading.Thread(target=create_application_load_balancer)
    thread4.start()
    thread4.join()

    thread5 = threading.Thread(target=ssl_listener_with_route53)
    thread5.start()
    thread5.join()

    thread6 = threading.Thread(target=wget_debug)
    thread7 = threading.Thread(target=elastic_beanstalk)
    thread8 = threading.Thread(target=rds_and_security_group)
    
    thread6.start()
    thread7.start()
    thread8.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread6.join()
    thread7.join()
    thread8.join()

    thread9 = threading.Thread(target=jumphost_for_rds_mysql_client)
    thread10 = threading.Thread(target=wget_for_elastic_beanstalk_alb)
    thread11 = threading.Thread(target=https_wget_for_elastic_beanstalk_alb)

    thread9.start()
    thread10.start()
    thread11.start()

   # Wait for all three of these to complete before proceeding to next block of threads
    thread9.join()
    thread10.join()
    thread11.join()

if __name__ == "__main__":
    main()
```


## UPDATES:

Added back in all the other modules for the modularized project.  There are a total of 11 modules at this time. The challenges were that there was no delay between first module (initialization of the EC2 instances) and the rest of the modules. The tomcat installation module requires that all instances be in Passed state in order to use the paramiko library to ssh into the EC2 instances and install tomcat. The public ip addreses need to be fully initialized on each instance to do this.  Adding a delay in the tomcat script got it working.

Moving the export of the instance ids and security group ids module to AFTER the tomcat installation module resolved another issue.  The export arrays were empty when this was executed as second module because the EC2 instances were not in fully running state. Once this was moved to the third module (non-multi-threaded), the fourth module which needs the instance id and security group id arrays started working.  This is because the second module (that is now the tomcat installation module) ensures that all EC2 instances are runnning and status checks are passed.  The fourth module, the manual ALB setup works fine now. After these changes the rest of the 11 modules ran fine including the beanstalk and RDS setups and the RDS jumphost as well as the wget stress EC2 generators for both the manual ALB and the beanstalk ALB instances (HTTP and HTTPS listeners).


## UPDATES:

Added large code changes for modulatization of the project, using packcage sequential_master_modules for the standalone python scripts.  master_script.py has non-parallelized version, and multi-threaded version and a multiprocessing version to optimize the deployment to AWS3. Broke off the RDS configuration from the beanstalk environment configuration as well so that can parallelize more effectively. RDS jumphost configuration added as well and it configures the RDS server with the basics for mydatabase.

There were several challenges encountered in making the threads 3 and 4 and 5 multi-threaded, in particular with threads 4 and 5 for http and https wget stress clients.  The error checking to checking instance status Ready and status and system checks ok was problematic.  Several changes had to  be made in this area.

Also making the code multi-threaded caused a lot of scope issues with the functions in the modules that are multi-threaded. The import of the libraries had to be done in the functions themselves to alleviate the scope issues.


## UPDATES:

See below as well.
Latest changes for AWS3 account are added elastic beanstalk environment and application and added wget stress traffic to that beanstalk URL (CNAME)

IAM class is required because instance_profile required to be attached to the beanstalk environment.  The instance_profile is a legacy object that holds the beanstalk role that has the folowing policies in it:
policies = [
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier',
    'arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier'



```
### boto3 classes:

elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')
eb_client = session.client('elasticbeanstalk')
iam_client = session.client('iam')
```



Also added HTTPS 443 listener to the elastic beanstalk ALB loadbalancer.  This requires a lot of code for the certificate. To get the SSL cert issues have to create a hosted domain in Route53 and add the A record of the DNS URL (CNAME) of the elastic beanstalk ALB loadbalancer, then once the CNAME is ready for the cert request add the CNAME to the Route53 hosted zone as a CNAME Record for DNS Validation of the cert so that it transitions into issued state. Once have the cert had to manually get the load_balancer_arn and target_group_arn of the existing ALB in the beanstalk environment and also use this newly issued certificate_arn to create the HTTPS 443 listener manually using the elbv2 boto3 class/method. The elasticbeanstalk method did not work for me.   
Finally add HTTPS traffic to the wget traffic generator EC2 instance so that HTTP and HTTPS are simultaneously sent to the the beanstalk ALB.

## ORIGINAL

This python project creates an ALB on AWS using a target group of 50 EC2 instances running an installed tomcat.  THe listener 
frontend is both https/ssl and http.   There is also a stress traffic EC2 generator that is also created to generate
stress traffic to the https listener.   The traffic can be monitored on the access logs of the ALB which are also 
configured using python. The following python classes are used to create this infrastructure using the boto3 SDK.


This uses a wrapper script to execute the modules as separate python script files.   

The SSL/TLS uses the acm class to create the cert. The CNAME has to be tested and so Route53 has to be employed to do this, using an A record to alias the ALB URL to the Route53 hosted zone. It works very well.

The following boto3 client classes are used so far:


```
class EC2.Client
class ElasticLoadBalancingv2.Client
class acm.Client

session.client('ec2')
elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')
```



Note: the autoscaling is not used for now as I need to create an effective destroy script as well for that. 



The wget EC2 instance stress generator:

```
Last login: Tue Apr  8 00:38:28 2025 from 172.31.21.52
ubuntu@ip-172-31-86-66:~$ ls
stress_test.sh
ubuntu@ip-172-31-86-66:~$ ps -ef |grep stress_test.sh
ubuntu      6336    6234  7 00:43 pts/1    00:00:00 grep --color=auto stress_test.sh
ubuntu@ip-172-31-86-66:~$ ls
stress_test.sh
ubuntu@ip-172-31-86-66:~$ tcpdump -i eth0 dst port 443
tcpdump: eth0: You don't have permission to capture on that device
(socket: Operation not permitted)
ubuntu@ip-172-31-86-66:~$ sudo tcpdump -i eth0 dst port 443
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:44:22.452595 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [.], ack 2974631937, win 459, options [nop,nop,TS val 2682466045 ecr 4009966254], length 0
00:44:22.456935 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [P.], seq 0:126, ack 1, win 459, options [nop,nop,TS val 2682466049 ecr 4009966254], length 126
00:44:22.458001 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [P.], seq 126:309, ack 205, win 458, options [nop,nop,TS val 2682466050 ecr 4009966330], length 183
00:44:22.462674 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [.], ack 2352, win 442, options [nop,nop,TS val 2682466055 ecr 4009966334], length 0
00:44:22.534144 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [F.], seq 309, ack 2352, win 442, options [nop,nop,TS val 2682466126 ecr 4009966334], length 0
00:44:22.534762 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [R], seq 3372935856, win 0, length 0
00:44:22.534804 IP ip-172-31-86-66.ec2.internal.43882 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [R], seq 3372935856, win 0, length 0
00:44:22.541068 IP ip-172-31-86-66.ec2.internal.43884 > ec2-34-204-127-255.compute-1.amazonaws.com.https: Flags [S], seq 3906347289, win 62727, options [mss 8961,sackOK,TS val 2
```

ALB Access logs show the loadbalancing to the backend:


The client and socket and the target EC2 instance (there are 50 of them) and the socket (8080)


```
https 2025-04-08T00:42:18.719308Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45808 172.31.87.99:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ea-440e2a275a742e0034a8b8c7" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:18.715000Z "forward" "-" "-" "172.31.87.99:8080" "200" "-" "-" TID_c058d0218cb28142a303b654f4f7c035
https 2025-04-08T00:42:18.906898Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45852 172.31.93.134:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ea-69b79ad0408104c00b50d2ef" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:18.903000Z "forward" "-" "-" "172.31.93.134:8080" "200" "-" "-" TID_d26d051d522b804498afa60e8922f3f5
https 2025-04-08T00:42:19.054746Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45890 172.31.84.229:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-054849b625c3282066db139e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.052000Z "forward" "-" "-" "172.31.84.229:8080" "200" "-" "-" TID_3ba0637db38e844ebde8a74f9887f966
https 2025-04-08T00:42:19.090741Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45892 172.31.84.204:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-1dc1077403b2551c412ef503" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.088000Z "forward" "-" "-" "172.31.84.204:8080" "200" "-" "-" TID_a24f144f195f5f498efaf0315dbf40d4
https 2025-04-08T00:42:19.108930Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45900 172.31.83.238:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-6238efbf5d8b11137ee036d4" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.104000Z "forward" "-" "-" "172.31.83.238:8080" "200" "-" "-" TID_1734351bfe9693479e8f4a23cb2d3bbc
https 2025-04-08T00:42:19.144177Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45912 172.31.89.170:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-2b943f924aa0d4627273f3ba" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.141000Z "forward" "-" "-" "172.31.89.170:8080" "200" "-" "-" TID_2442f548a6429c40acf4a06e73fbb920
https 2025-04-08T00:42:19.181414Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45920 172.31.83.192:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-6f4ae2d26fa9a3194b558600" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.176000Z "forward" "-" "-" "172.31.83.192:8080" "200" "-" "-" TID_536249c7882634459b30112fa081086a
https 2025-04-08T00:42:19.289057Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45952 172.31.81.228:8080 0.002 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-197042313f8d077c34fabf32" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.284000Z "forward" "-" "-" "172.31.81.228:8080" "200" "-" "-" TID_f437e2f588025e489488c3d26be213f8
https 2025-04-08T00:42:19.377019Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45968 172.31.82.19:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-549336667d9a20f309dc7f01" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.373000Z "forward" "-" "-" "172.31.82.19:8080" "200" "-" "-" TID_a3b426c20cf58e418b7d714b7ab0492e
https 2025-04-08T00:42:19.409220Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45990 172.31.87.16:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-5a4da9a945238de25a84284e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.407000Z "forward" "-" "-" "172.31.87.16:8080" "200" "-" "-" TID_6b3362a719b6c148a01ce8c0d0235b29
https 2025-04-08T00:42:19.444768Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:45998 172.31.85.85:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-0c289d8271aeb9603917d732" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.442000Z "forward" "-" "-" "172.31.85.85:8080" "200" "-" "-" TID_6758638dc9f4be4d93091ac359beef6b
https 2025-04-08T00:42:19.463656Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46008 172.31.86.16:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-4984f3394a758b1968b9da58" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.458000Z "forward" "-" "-" "172.31.86.16:8080" "200" "-" "-" TID_9f4a2d3c5cee874ea5b3e71dc0a292ea
https 2025-04-08T00:42:19.510454Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46032 172.31.93.38:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-3370f07b51979a5e080d40b1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.506000Z "forward" "-" "-" "172.31.93.38:8080" "200" "-" "-" TID_6329eb37a865a749aa27d0b9a4fea65e
https 2025-04-08T00:42:19.577794Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46034 172.31.94.59:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-0e383ffa217f8529600d4fdd" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.574000Z "forward" "-" "-" "172.31.94.59:8080" "200" "-" "-" TID_6e5df171195dcf4887dc79e34de4ebd0
https 2025-04-08T00:42:19.700430Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46052 172.31.89.105:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-2bf3c307349ce2e46172e95f" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.696000Z "forward" "-" "-" "172.31.89.105:8080" "200" "-" "-" TID_c1378c55075d2446850f3dab0b442f94
https 2025-04-08T00:42:19.864127Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46074 172.31.95.109:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-16fc7e72604f5fae04048cdd" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.860000Z "forward" "-" "-" "172.31.95.109:8080" "200" "-" "-" TID_5aa286b3f793e54ea2a312d01900eae6
https 2025-04-08T00:42:19.938048Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46088 172.31.90.94:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-323f680a74ea64e53975dcda" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.934000Z "forward" "-" "-" "172.31.90.94:8080" "200" "-" "-" TID_5b7085dddad858419ce7c68f82fe743c
https 2025-04-08T00:42:19.987400Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46094 172.31.81.138:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470eb-261e946d423b8854525d164e" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:19.985000Z "forward" "-" "-" "172.31.81.138:8080" "200" "-" "-" TID_7698b513a8a13341aa145df3f68036dc
https 2025-04-08T00:42:20.023750Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46116 172.31.84.185:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-4b4a5a66581cef4319ebd5f6" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.020000Z "forward" "-" "-" "172.31.84.185:8080" "200" "-" "-" TID_a55fab4bce194c4b83e0ff88d3f1d63b
https 2025-04-08T00:42:20.059098Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46126 172.31.92.63:8080 0.001 0.003 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-76eadfc60d6b8b42602ed0b1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.054000Z "forward" "-" "-" "172.31.92.63:8080" "200" "-" "-" TID_cee51ee452a7b74780e6e8880c51f406
https 2025-04-08T00:42:20.120100Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46142 172.31.94.160:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-683ecd4b140e253a0827bee6" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.116000Z "forward" "-" "-" "172.31.94.160:8080" "200" "-" "-" TID_aa953d4641c4434cb032f2aecf315933
https 2025-04-08T00:42:20.219465Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46146 172.31.83.105:8080 0.001 0.001 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-088c40af730a61d80044f8d2" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.217000Z "forward" "-" "-" "172.31.83.105:8080" "200" "-" "-" TID_97e7b25a5aa8604f9e843fb20c255eee
https 2025-04-08T00:42:20.445742Z app/tomcat-load-balancer/d12d886025a14d3f 52.91.163.121:46204 172.31.88.90:8080 0.001 0.002 0.000 200 200 154 2118 "GET https://loadbalancer.holinessinloveofchrist.com:443/ HTTP/1.1" "Wget/1.21.2" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-1:590183769797:targetgroup/tomcat-target-group/21175dd5b85e97d7 "Root=1-67f470ec-762531377c53150428c829d1" "loadbalancer.holinessinloveofchrist.com" "arn:aws:acm:us-east-1:590183769797:certificate/6ab5d190-7f04-42a9-ba11-1e103388e7e3" 0 2025-04-08T00:42:20.443000Z "forward" "-" "-" "172.31.88.90:8080" "200" "-" "-" TID_0c5934f18f4d81489860565f1b94e0a1

```



