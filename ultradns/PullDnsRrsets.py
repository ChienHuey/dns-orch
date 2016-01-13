# Script to retrieve DNS information using the UltraDNS REST API
# Script accepts two parameters as follows
# 
# python PullDnsRrsets.py <username> <password> <path to place zone files>
#
# requires bucket in S3 to be created beforehand. Zone files will be zipped up in a file with name
# YYYY-MM-DD_zone_file_extract.zip.
#
# @param    username        UltraDNS username
# @param    password        UltraDNS password
# @param    directory-path  directory where you want to store the zone files - can be relative or absolute path
# @param    role-arn        IAM role ARN granting post access to the S3 bucket
# @param    s3bucket        name of S3 bucket to upload zone files as

import boto3
import ultra_rest_client
import datetime
import errno
import os
import re
import shutil
import sys
import zipfile


# function to create directory with zone file information
def create_zone_file_directory(zone_file_path):
    try:
        os.makedirs(zone_file_path)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            shutil.rmtree(zone_file_path)
            os.makedirs(zone_file_path)
        else:
            raise


# pre-compiled regex filters
record_type_regex = re.compile(r'([A-Z]+)')
soa_hosts_regex = re.compile(r'(.+?(?=\d{10}))')
soa_numbers_regex = re.compile(r'\s(\d+)')


# function to format UltraDNS type info
#
# @param    ultra_type  the rrtype data coming back from the UltraDNS REST API
# @return   string with the DNS resource record type (e.g. A, CNAME, TXT, SOA, etc)
def convert_ultra_type_to_bind(ultra_type):
    return record_type_regex.match(ultra_type)


# parses the SOA data from UltraDNS and returns in BIND format
#
# @param    record_type the DNS resource record type (e.g. A, CNAME, TXT, SOA, etc)
# @param    soa_data    the rdata data coming back from the UltraDNS REST API
# @return   string with the SOA record with proper formatting per BIND file format specs
def parse_soa_data(record_type, soa_data):
    match = soa_hosts_regex.match(soa_data)
    if match is not None:
        soa_hosts = match.group()
    else:
        soa_hosts = "None"
    soa_numbers = soa_numbers_regex.findall(soa_data)
    if soa_numbers is not None:
        soa_serial = soa_numbers[0]
        soa_refresh = soa_numbers[1]
        soa_retry = soa_numbers[2]
        soa_expire = soa_numbers[3]
        soa_minimum = soa_numbers[4]
        bind_record = "@ IN {0} {1} (\n\t\t\t\t{2} ; serial\n\t\t\t\t{3} ; refresh\n\t\t\t\t{4} ; retry\n\t\t\t\t{5} ;\
            expire\n\t\t\t\t{6} ; minimum\n\t\t\t\t)\n".format(
            record_type, soa_hosts, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum)
    else:
        bind_record = None

    return bind_record


# parse generic DNS text record from UltraDNS and returns in BIND format

def parse_rrset_data(record_type, record_owner, record_data, record_ttl):
    resource_records = ""
    for resource_row in record_data:
        resource_record = "{0}\t{1}\tIN\t{2}\t{3}\n".format(record_owner, record_ttl, record_type, resource_row)
        resource_records += resource_record

    return resource_records


# function to accept type, data and TTL and return properly formatted BIND format file
def convert_ultrarestapi_to_bind(ultra_owner, ultra_type, ultra_data, ultra_ttl):
    record_type = convert_ultra_type_to_bind(ultra_type).group()

    bind_record = ""

    # based on the bind record type, format the text accordingly
    if record_type == "SOA":
        # do nothing since the SOA record has already been handled
        pass
    else:
        bind_record = parse_rrset_data(record_type, ultra_owner, ultra_data, ultra_ttl)

    return bind_record


username = sys.argv[1]
password = sys.argv[2]
path = sys.argv[3]
role_arn = sys.argv[4]
s3_bucket_name = sys.argv[5]
region_name = "us-east-1"
use_http = 'False'
domain = 'restapi.ultradns.com'

# clean up zone files from previous run and recreate the folder
create_zone_file_directory(path)

# change into the zone file directory
os.chdir(path)

# connect to the UltraDNS REST API service
c = ultra_rest_client.RestApiClient(username, password, 'True' == use_http, domain)
account_details = c.get_account_details()
account_name = account_details[u'accounts'][0][u'accountName']

all_zones = c.get_zones_of_account(account_name, offset=0, limit=5, reverse=False)  # 47

num_arrays = len(all_zones)
num_zones = len(all_zones[u'zones'])

zones = all_zones[u'zones']

# iterate through all the zones returned
for index in range(0, len(zones)):
    zone_name = zones[index][u'properties'][u'name']
    print zone_name

    # create zone data file, overwrite existing file
    zone_file_name = "{0}.txt".format(zone_name)
    zone_data_file = open(zone_file_name, "w")
    zone_data_file.write("$ORIGIN {0}\n".format(zone_name))

    # pull the SOA record first and parse it
    soa_rrsets = c.get_rrsets_by_type(zone_name, "SOA")[u'rrSets']
    if len(soa_rrsets) > 0:
        soa_rrset = soa_rrsets[0]
        soa_record = parse_soa_data("SOA", soa_rrset[u'rdata'][0])
        zone_data_file.write(soa_record)
        print soa_record

    # extract the RRSet for the zone
    zones_rrsets = c.get_rrsets(zone_name)[u'rrSets']

    # iterate through all the RRSets for a given zone
    for rrset in zones_rrsets:
        zone_data = "owner: {0} type: {1} data: {2} TTL: {3}\n".format(rrset[u'ownerName'], rrset[u'rrtype'],
                                                                       rrset[u'rdata'], rrset[u'ttl'])
        bind_file_data = convert_ultrarestapi_to_bind(
            rrset[u'ownerName'], rrset[u'rrtype'], rrset[u'rdata'], rrset[u'ttl'])
        print bind_file_data
        zone_data_file.write(bind_file_data)

    # remember to close the file
    zone_data_file.close()

# zip up all the zones into a single file
os.chdir("..")
today = datetime.date.today()
filename = "{0}_zone_file_extract.zip".format(today.isoformat())
zone_files_zipfile = zipfile.ZipFile(filename, 'w')
for root, dirs, files in os.walk(path):
    for zone_file in files:
        zone_files_zipfile.write(os.path.join(root, zone_file))
zone_files_zipfile.close()

# upload file to S3 bucket
client = boto3.client('sts')
assumedRoleObject = client.assume_role(
    RoleArn='{0}'.format(role_arn),
    RoleSessionName='ultradns_zone_upload'
)
aws_access_key = assumedRoleObject['Credentials']['AccessKeyId']
aws_secret_access_key = assumedRoleObject['Credentials']['SecretAccessKey']
aws_session_token = assumedRoleObject['Credentials']['SessionToken']

aws_session = boto3.session.Session(aws_access_key, aws_secret_access_key, aws_session_token, region_name)
s3 = aws_session.resource('s3')
s3.meta.client.upload_file(filename, s3_bucket_name, filename)
