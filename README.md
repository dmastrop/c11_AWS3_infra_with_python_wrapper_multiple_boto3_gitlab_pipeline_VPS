## UPDATES: BENCHMARKING part5: 

Sanity testing of 200 and 400 instances

200 instances with 10 chunk size and 10 threads for 20 processes ran fine. All instances have tomcat installed. So the issue is clearly with the number of processes < 25 and not number of instances, or SSH connections, etc.

400 instances with 20 chunk and 20 threads also running. Had to increase gitlab runner log capacity from 10 MB to 50 MB. TThis worked as well confirming that it is the  number of processes and nothing else. 

The increase in swap from 1GB to 4GB will help the VPS when scaling to 100+ processes as the python code is refactored to support this hyper-scaling corner case.


### Code refactoring to deal with the process hyper-scaling issue > 25:






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

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R 100.0   0.0  25:23.80 kswapd0                                            
1998254 root      20   0 1139656  10832   2128 S  41.5   0.1   3:50.24 fail2ban-server                                    
2005387 1001      20   0 1238948   9132   1196 S  28.9   0.1   0:47.86 go-camo    




    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                            
     77 root      20   0       0      0      0 R  72.1   0.0  25:32.10 kswapd0                                            
    456 root      20   0 2241208  13612   1652 S  23.4   0.1  28:28.77 containerd                                         
2616745 112       20   0  122344  79376   1396 D  21.4   0.5   0:01.59 amavisd-new                                        
   1302 root      20   0 3693788  34924   1900 S  18.8   0.2 210:26.35 dockerd   


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


Further detail in main():

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





## UPDATES:

Running on 11 modules in multi-processing master script. This is running fine. This is using the function approach as well from the master script. Running on 6 processes because the VPS has 6 cores.


## UPDATES:

Now running all 11 modules in multi-threaded environment, with each of 11 modules running as a dedicated thread and grouping several of them for concurrency to speed up the infra rollout. The execu function call in the master python script ended up causing many scope related issues in the first 6 modules. I converted the entire script to a function call based multi-threading and wrapped all the python files in the package directory in dedicated function that is called from the master. The master python script is below for reference.   This runs very well all the way through without any scope related issues.

commit:
    major overhaul of multithreaded set up for all 11 modules. The first 6 modules had several scope related issues and so converted the master python script use function calls to the modules rather than exec function which has scoping issues. Had to wrap all modules in their respective function call names. Referring to them by path name rather than module object name but either approach is fine


The thread that takes the longest, the installation of tomcat on each of the 50 EC2 instances cannot be parallelized with any of the other treads because the EC2 instances are in the target group and tomcat has to be running so that the ALB passes target health checks when the ALB is created.


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

### boto3 classes:

elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')
eb_client = session.client('elasticbeanstalk')
iam_client = session.client('iam')

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



class EC2.Client
class ElasticLoadBalancingv2.Client
class acm.Client

session.client('ec2')
elb_client = session.client('elbv2')
acm_client = session.client('acm')
route53_client = session.client('route53')
autoscaling_client = session.client('autoscaling')

Note: the autoscaling is not used for now as I need to create an effective destroy script as well for that. 



The wget EC2 instance stress generator:


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


ALB Access logs show the loadbalancing to the backend:


The client and socket and the target EC2 instance (there are 50 of them) and the socket (8080)

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





