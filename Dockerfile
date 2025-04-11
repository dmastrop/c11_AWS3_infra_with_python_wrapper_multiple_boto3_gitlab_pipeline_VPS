FROM python:3.11.9
WORKDIR /aws_EC2
ENV PYTHONUNBUFFERED=1

COPY ./aws_EC2_boto3_class /aws_EC2
RUN pip install --no-cache-dir -r requirements.txt
#CMD ["python", "master_sequential_for_docker_run_in_linux_order_with_variable_delays_USE.py"]
CMD ["python", "-u", "master_sequential_for_docker_run_in_linux_order_with_variable_delays_USE_AWS3_ONLY_debug.py"]
