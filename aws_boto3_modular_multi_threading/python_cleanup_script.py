
import re

def remove_non_printable_chars(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Remove non-printable characters
    cleaned_content = re.sub(r'[^\x20-\x7E]', '', content)
    
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(cleaned_content)

# Replace with the path to your script file
file_path = '/aws_EC2/master_sequential_for_docker_run_in_linux_order_with_variable_delays_USE_AWS3_ONLY_debug.py'
remove_non_printable_chars(file_path)

