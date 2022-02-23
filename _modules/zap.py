"""
# Details
Version: 0.1
Purpose: This module runs zap on an application
Last updated: 02/23/2022
By: Michael Roberts

# Background
ZAP is a dynamic application security testing tool that runs active tests against
the running application. These tests identify potential security vulnerabilities
within the application and backing APIs, equipping engineers with the information
to fix any found issues.

# Usage
## What is accomplished by this module?


## What is the expected outcome of this module


This module is compatible with both soarcast and CLI salt interactions.

# Preflight
This module depends on the zap salt state to be run first.
"""


import logging, sys, os, time, platform, subprocess

log = logging.getLogger(__name__)

def __virtual__():
    """
    Verify all python dependencies and OS requirements are met
    """
    modules = ['logging','sys','os','time','platform','subprocess']
    HAS_DEPS = False
    if all(mod in str(sys.modules) for mod in modules):
        HAS_DEPS = True
    if HAS_DEPS==False:
        log.error('Missing Python dependencies.')
        return False
    if platform.system()!='Linux':
        log.error('Minion OS does not match module specifications')
        return False
    return True


def run(target_app=None, output_format=None, redis_write_key=None, redis_write_key=None,
    redis_tls_host=None, redis_tls_port=None, redis_tls_password=None):
    """
    This function describes all SGs in a VPC and uplaod to S3. If the S3 upload
    fails or is not desired the file can be found locally here
    /tmp/extract_sg/aws_sg_<EPOCH_TIME>.<json/csv>

    Pillar Example:
        target_app:     google.com      Application to target
        output_format:  txt             txt and json outputs supported

        redis_write_key:               key that file location will be written to
        redis_tls_host:
        redis_tls_port:
        redis_tls_password:

    CLI Example:
        *With pillars set:
        salt <minion_name> zap.run

        *Without pillars set:
        salt <minion_name> extract_sg.run <target_app> <output_format> <redis_write_key>
    """

    # Manditory module pillars
    target_app = target_app or __pillar__.get('target_app')
    output_format = output_format or __pillar__.get('output_format')

    # Setup redis variables
    redis_write_key = redis_write_key or __pillar__.get('redis_write_key')
    redis_tls_host = redis_tls_host or __pillar__.get('redis_tls_host')
    redis_tls_port = redis_tls_port or __pillar__.get('redis_tls_port')
    redis_tls_password = redis_tls_password or __pillar__.get('redis_tls_password')

    # Create save filename and ensure that path exists
    output_path = "/tmp/zap/"
    save_file_name = output_path + "zap_{}.{}".format(str(time.time()), str(output_format))
    file_path = output_path + save_file_name
    _ensure_dir_exists(output_path)

    # Pull zap docker container and capture output in savefile
    subprocess.run(['docker', 'pull', 'owasp/zap2docker-stable'])
    output = subprocess.run(['docker', 'run', '-t', 'owasp/zap2docker-weekly', 'zap-baseline.py',
        '-t', target_app], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(save_file_name, 'w') as f:
        f.write(output.stdout.decode())

    # write location of file to redis_write_key
    try:
        if redis_tls_host and redis_tls_port and redis_tls_password:
            r = redis.Redis(host=redis_tls_host, port=redis_tls_port, password=redis_tls_password, ssl=True, ssl_cert_reqs=None)
            # Test Redis connection to make sure it is valid. This will throw an error if invalid.
            r.smembers(redis_write_key)
    except Exception as e:
        log.error("Could not connect to Redis. Make sure that all redis variables are correct.")
        _check_sentry()
        return "Could not connect to Redis. Make sure that all redis variables are correct."
    r.sadd(redis_write_key, file_path)
    
    return True

def _ensure_dir_exists(directory_to_check):
    """
    This function creates a directory if it does not already exist and changes
    the working directory to it
    """

    try:
        os.makedirs(directory_to_check, exist_ok=True)
        os.chdir(directory_to_check)
    except Exception as e:
        log.error("Could not create directory {}. \n{}".format(directory_to_check, e))