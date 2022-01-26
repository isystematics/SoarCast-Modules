"""
# Details
Version: 0.2
Purpose: This module extracts security group information from aws from the desired VPC
Last updated: 01/26/2022
By: Michael Roberts

# Background
A security group acts as a virtual firewall for your EC2 instances to control inbound
and outbound traffic. These are set in a VPC and each security group has ingress and
egress rules associated with it.

# Usage
## What is accomplished by this module?
This function exports either a CVS or JSON formatted file containing the rules for
all security groups under the specified VPC. This is both a standalone module and a
module that can be linked to others.

## What is the expected outcome of this module
This module will authenticate to aws either with or without STS, find the specified
VPC, describe the security groups within that VPC, save it locally to
/tmp/extract_sg/aws_sg_<EPOCH_TIME>.<json/csv>, and then upload to s3 if credentials are provided.

This module is compatible with both soarcast and CLI salt interactions.

# Preflight
This module depends on the extract_sg salt state to be run first.
"""


import boto3, logging, sys, os, json, csv, time, platform

log = logging.getLogger(__name__)

def __virtual__():
    """
    Verify all python dependencies and OS requirements are met
    """
    modules = ['boto3','logging','sys','os','json','csv','time','platform']
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


def run(target_vpc_id=None, target_region=None, output_format=None, aws_key_id=None,
    aws_key=None, s3_bucket_name=None, s3_key_id=None, s3_key=None, aws_role_arn=None,
    aws_session_name=None, aws_external_id=None):
    """
    This function describes all SGs in a VPC and uplaod to S3. If the S3 upload
    fails or is not desired the file can be found locally here
    /tmp/extract_sg/aws_sg_<EPOCH_TIME>.<json/csv>

    Pillar Example:
        target_vpc_id:  vpc-dfgh....
        target_region:  us-east-1
        output_format:  json            supported options: json and csv
        aws_key_id:     AKIA...
        aws_key:        rikj...

        s3_bucket_name: mybucke...      (optional)
        s3_key_id:      AKIA...         (optional)
        s3_key:         OQoK...         (optional)

        aws_role_arn:           (optional) aws arn of the role to assume
        aws_session_name:       (optional) session name for the role assumed
        aws_external_id:        (optional) aws external id for the role assumed

    CLI Example:
        *With pillars set:
        salt <minion_name> extract_sg.run

        *Without pillars set:
        salt <minion_name> extract_sg.run <target_vpc_id> <target_vpc>
    """

    # Manditory module pillars
    target_vpc_id = target_vpc_id or __pillar__.get('target_vpc_id')
    target_region = target_region or __pillar__.get('target_region')
    output_format = output_format or __pillar__.get('output_format')
    aws_key_id = aws_key_id or __pillar__.get('aws_key_id')
    aws_key = aws_key or __pillar__.get('aws_key')
    if any([target_vpc_id==None, output_format==None, aws_key_id==None, aws_key==None]):
        log.error("Mandatory perameters not set for extract_sg module")

    # S3 pillars
    s3_bucket_name = s3_bucket_name or __pillar__.get('s3_bucket_name')
    s3_key_id = s3_key_id or __pillar__.get('s3_key_id')
    s3_key = s3_key or __pillar__.get('s3_key')
    if any([s3_bucket_name==None, s3_key_id==None, s3_key==None]):
        log.error("S3 perameters not set for extract_sg module, will not upload to S3")

    # STS pillars
    aws_role_arn = aws_role_arn or __pillar__.get('aws_role_arn')
    aws_session_name = aws_session_name or __pillar__.get('aws_session_name')
    aws_external_id = aws_external_id or __pillar__.get('aws_external_id')
    if any([aws_role_arn==None, aws_session_name==None, aws_external_id==None]):
        log.error("STS perameters not set for extract_sg module, running without STS")

    # Create save filename and ensure that path exists
    extract_sg_path = "/tmp/extract_sg/"
    save_file_name = extract_sg_path + "aws_sg_{}.{}".format(str(time.time()), str(output_format))
    _ensure_dir_exists(extract_sg_path)

    # If STS is being used, get temp creds
    if all([aws_role_arn!=None, aws_session_name!=None, aws_external_id!=None]):
        try:
            certs = _aws_sts_assume_role(aws_key_id, aws_key, aws_role_arn, aws_session_name, aws_external_id)
            [aws_key_id, aws_key, scan_source_token] = certs
            sts_assume_role = True
            log_file +="sts_assume creds success\n"
        except Exception as e:
            log.error("There was an error assuming STS role. \n{}".format(e))
    else:
        sts_assume_role = False

    # Setup ec2 client
    if sts_assume_role==True:
        ec2_client = boto3.client('ec2', aws_access_key_id=aws_key_id, aws_secret_access_key=aws_key,
            aws_session_token=aws_sts_token, region_name=target_region)
    else:
        ec2_client = boto3.client('ec2', aws_access_key_id=aws_key_id, aws_secret_access_key=aws_key,
            region_name=target_region)

    # Get SG data from target_vpc_id
    try:
        response = ec2_client.describe_security_groups()
        vpc_data= {}
        vpc_data['Vpc_Id'] = target_vpc_id
        for sg in response['SecurityGroups']:
            if sg['VpcId'] == target_vpc_id:
                vpc_data[sg['GroupId']] = {'IpPermissions': sg['IpPermissions']}, {'IpPermissionsEgress': sg['IpPermissionsEgress']}
    except ClientError as e:
        log.error("An error occured while describing security groups in extract_sg module. \n{}".format(e))

    # Save as desired format
    if output_format == 'json':
        try:
            with open(save_file_name, 'w') as fp:
                json.dump(vpc_data, fp)
        except Exception as e:
            log.error("An error occured while saving {} in extract_sg module. \n{}".format(save_file_name, e))
    elif output_format == 'csv':
        try:
            with open(save_file_name, "w") as csv_file:
                csv_file.write('VPC: {}\n'.format(target_vpc_id))
                for key, value in vpc_data.items():
                    if 'Vpc' not in key:
                        sg_ingress = []
                        sg_engress = []
                        for item in value[0]['IpPermissions']:
                            sg_ingress.append(item['IpRanges'])
                        for item in value[1]['IpPermissionsEgress']:
                            sg_engress.append(item['IpRanges'])
                        csv_file.write('Security Group: {}\n'.format(key))     # todo change to csv write
                        csv_file.write('Ingress Rules\n')     # todo change to csv write
                        for ingress in sg_ingress:
                            for rule in ingress:
                                line = ''
                                for key in rule.keys():
                                    line += '{}: {}  \n'.format(key, rule[key])
                                csv_file.write(line)     # todo change to csv write
                        csv_file.write('Engress Rules\n')     # todo change to csv write
                        for engress in sg_engress:
                            for rule in engress:
                                line = ''
                                for key in rule.keys():
                                    line += '{}: {}  \n'.format(key, rule[key])
                                csv_file.write(line)     # todo change to csv write
        except Exception as e:
            log.error("An error occured while writing security groups to csv in extract_sg module. \n{}".format(e))
    else:
        log.error("output_format variable not set correctly in extract_sg module. Use either 'csv' or 'json'")

    # Save to S3
    if s3_key!=None and s3_key_id!=None and s3_bucket_name!=None:
        s3_filename = "AWS-SG-{}.{}".format(str(time.time()), output_format)
        s3_resource = boto3.resource('s3',
                                    aws_access_key_id=s3_key_id,
                                    aws_secret_access_key=s3_key)
        s3_resource.meta.client.upload_file(Filename=save_file_name,
                                    Bucket=s3_bucket_name,
                                    Key=s3_filename)
        log.error('{} saved to s3\n'.format(s3_filename))

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


def _aws_sts_assume_role(aws_key_id, aws_key, aws_role_arn, aws_session_name, aws_external_id):
    """
    version: 0.1
    this funtion uses the provided aws creds to assume another aws role
    input perameters:
        aws_key_id:        starting aws_key_id
        aws_key:           starting aws_key
        aws_role_arn:      aws arn of the role to assume
        aws_session_name:  session name for the role assumed
        aws_external_id:   aws external id for the role assumed
    output:
        assumed_role_key_id:    aws key id for the role assumed
        assumed_role_key:       aws key for the role assumed
        assumed_role_token:     aws token for the role assumed
    return:
        [assumed_role_key_id, assumed_role_key, assumed_role_token]
    """

    # check all inputs are not None and log if any are
    in_var = [aws_key_id, aws_key, aws_role_arn, aws_session_name, aws_external_id]
    in_var_names = ["aws_key_id", "aws_key", "aws_role_arn", "aws_session_name", "aws_external_id"]
    for iv in range(len(in_var)):
        if in_var[iv]==None:
            log.error("The {} parameter is not set in prowler.aws_sts_assume_role function.".format(in_var_names[iv]))
            _check_sentry()
            return "The {} parameter is not set in prowler.aws_sts_assume_role function.".format(in_var_names[iv])

    # configure aws, run sts assume role, capture output, and return
    sts_client = boto3.client('sts',aws_access_key_id=aws_key_id, aws_secret_access_key=aws_key)
    assumed_role_object=sts_client.assume_role(RoleArn=aws_role_arn,
                    RoleSessionName=aws_session_name, ExternalId=aws_external_id)
    credentials=assumed_role_object['Credentials']
    creds = [credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]]
    return creds
