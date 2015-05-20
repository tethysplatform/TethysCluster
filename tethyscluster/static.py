# Copyright 2015 Scott Christensen
#
# This file is part of TethysCluster
#
# TethysCluster is a modified version of StarCluster (Copyright 2009-2014 Justin Riley)
#
# TethysCluster is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# TethysCluster is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with TethysCluster. If not, see <http://www.gnu.org/licenses/>.

"""
Module for storing static data structures
"""
import os
import sys
import getpass
import tempfile


def __expand_all(path):
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    return path


def __expand_all_in_list(lst):
    for i, path in enumerate(lst):
        lst[i] = __expand_all(path)
    return lst


def __makedirs(path, exit_on_failure=False):
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError:
            if exit_on_failure:
                sys.stderr.write("!!! ERROR - %s *must* be a directory\n" %
                                 path)
    elif not os.path.isdir(path) and exit_on_failure:
        sys.stderr.write("!!! ERROR - %s *must* be a directory\n" % path)
        sys.exit(1)


def create_tc_config_dirs():
    __makedirs(TETHYSCLUSTER_CFG_DIR, exit_on_failure=True)
    __makedirs(TETHYSCLUSTER_PLUGIN_DIR)
    __makedirs(TETHYSCLUSTER_LOG_DIR)

def get_version():
    import re
    with open('README.rst','r') as f:
        text = f.read()
        version = re.search(':Version: ([\.?\d]*)',text).group(1)
        return version


VERSION = get_version()
PID = os.getpid()
TMP_DIR = tempfile.gettempdir()
if os.path.exists("/tmp"):
    TMP_DIR = "/tmp"
CURRENT_USER = 'unknown_user'
try:
    CURRENT_USER = getpass.getuser()
except:
    pass
SSH_TEMPLATE = 'ssh %(opts)s %(user)s@%(host)s'

TETHYSCLUSTER_CFG_DIR = os.path.join(os.path.expanduser('~'), '.tethyscluster')
TETHYSCLUSTER_CFG_FILE = os.path.join(TETHYSCLUSTER_CFG_DIR, 'config')
TETHYSCLUSTER_PLUGIN_DIR = os.path.join(TETHYSCLUSTER_CFG_DIR, 'plugins')
TETHYSCLUSTER_LOG_DIR = os.path.join(TETHYSCLUSTER_CFG_DIR, 'logs')
TETHYSCLUSTER_RECEIPT_DIR = "/var/run/tethyscluster"
TETHYSCLUSTER_RECEIPT_FILE = os.path.join(TETHYSCLUSTER_RECEIPT_DIR, "receipt.pkl")
STARCLUSTER_OWNER_ID = 342652561657

CLOUD_PROVIDERS = {'aws':'AWS', 'azure':'Azure'}

DEBUG_FILE = os.path.join(TETHYSCLUSTER_LOG_DIR, 'debug.log')
SSH_DEBUG_FILE = os.path.join(TETHYSCLUSTER_LOG_DIR, 'ssh-debug.log')
AWS_DEBUG_FILE = os.path.join(TETHYSCLUSTER_LOG_DIR, 'aws-debug.log')
CRASH_FILE = os.path.join(TETHYSCLUSTER_LOG_DIR, 'crash-report-%d.txt' % PID)

# TethysCluster BASE AMIs (us-east-1)
BASE_AMI_32 = "ami-9bf9c9f2"
BASE_AMI_64 = "ami-3393a45a"
BASE_AMI_HVM = "ami-6b211202"

SECURITY_GROUP_PREFIX = "@tc-"
SECURITY_GROUP_TEMPLATE = SECURITY_GROUP_PREFIX + "%s"
VOLUME_GROUP_NAME = "volumecreator"
VOLUME_GROUP = SECURITY_GROUP_PREFIX + VOLUME_GROUP_NAME

# Cluster group tag keys
VERSION_TAG = SECURITY_GROUP_PREFIX + 'version'
CORE_TAG = SECURITY_GROUP_PREFIX + 'core'
USER_TAG = SECURITY_GROUP_PREFIX + 'user'
MAX_TAG_LEN = 255

# Internal TethysCluster userdata filenames
UD_PLUGINS_FNAME = "_tc_plugins.txt"
UD_VOLUMES_FNAME = "_tc_volumes.txt"
UD_ALIASES_FNAME = "_tc_aliases.txt"

INSTANCE_METADATA_URI = "http://169.254.169.254/latest"
INSTANCE_STATES = ['pending', 'running', 'shutting-down',
                   'terminated', 'stopping', 'stopped']
VOLUME_STATUS = ['creating', 'available', 'in-use',
                 'deleting', 'deleted', 'error']
VOLUME_ATTACH_STATUS = ['attaching', 'attached', 'detaching', 'detached']

AWS_INSTANCE_TYPES = {
    't1.micro': ['i386', 'x86_64'],
    't2.micro': ['i386', 'x86_64'],
    't2.small': ['i386', 'x86_64'],
    't2.medium': ['i386', 'x86_64'],
    'm1.small': ['i386', 'x86_64'],
    'm1.medium': ['i386', 'x86_64'],
    'm1.large': ['x86_64'],
    'm1.xlarge': ['x86_64'],
    'c1.medium': ['i386', 'x86_64'],
    'c1.xlarge': ['x86_64'],
    'm2.xlarge': ['x86_64'],
    'm2.2xlarge': ['x86_64'],
    'm2.4xlarge': ['x86_64'],
    'm3.medium': ['x86_64'],
    'm3.large': ['x86_64'],
    'm3.xlarge': ['x86_64'],
    'm3.2xlarge': ['x86_64'],
    'r3.large': ['x86_64'],
    'r3.xlarge': ['x86_64'],
    'r3.2xlarge': ['x86_64'],
    'r3.4xlarge': ['x86_64'],
    'r3.8xlarge': ['x86_64'],
    'cc1.4xlarge': ['x86_64'],
    'cc2.8xlarge': ['x86_64'],
    'cg1.4xlarge': ['x86_64'],
    'g2.2xlarge': ['x86_64'],
    'cr1.8xlarge': ['x86_64'],
    'hi1.4xlarge': ['x86_64'],
    'hs1.8xlarge': ['x86_64'],
    'c3.large': ['x86_64'],
    'c3.xlarge': ['x86_64'],
    'c3.2xlarge': ['x86_64'],
    'c3.4xlarge': ['x86_64'],
    'c3.8xlarge': ['x86_64'],
    'i2.xlarge': ['x86_64'],
    'i2.2xlarge': ['x86_64'],
    'i2.4xlarge': ['x86_64'],
    'i2.8xlarge': ['x86_64'],
}

AZURE_INSTANCE_TYPES = {
    'ExtraSmall': ['x86_64'],
    'Small': ['x86_64'],
    'Medium': ['x86_64'],
    'Large': ['x86_64'],
    'ExtraLarge': ['x86_64'],
    'A5': ['x86_64'],
    'A6': ['x86_64'],
    'A7': ['x86_64'],
    'A8': ['x86_64'],
    'A9': ['x86_64'],
    'Basic_A0': ['x86_64'],
    'Basic_A1': ['x86_64'],
    'Basic_A2': ['x86_64'],
    'Basic_A3': ['x86_64'],
    'Basic_A4': ['x86_64'],
    'Standard_D1': ['x86_64'],
    'Standard_D2': ['x86_64'],
    'Standard_D3': ['x86_64'],
    'Standard_D4': ['x86_64'],
    'Standard_D11': ['x86_64'],
    'Standard_D12': ['x86_64'],
    'Standard_D13': ['x86_64'],
    'Standard_D14': ['x86_64'],
    'Standard_G1': ['x86_64'],
    'Standard_G2': ['x86_64'],
    'Sandard_G3': ['x86_64'],
    'Standard_G4': ['x86_64'],
    'Standard_G5': ['x86_64'],
}

INSTANCE_TYPES = dict(AZURE_INSTANCE_TYPES)
INSTANCE_TYPES.update(AWS_INSTANCE_TYPES)

T1_INSTANCE_TYPES = ['t1.micro']

T2_INSTANCE_TYPES = ['t2.micro', 't2.small', 't2.medium']

SEC_GEN_TYPES = ['m3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge']

CLUSTER_COMPUTE_TYPES = ['cc1.4xlarge', 'cc2.8xlarge']

CLUSTER_GPU_TYPES = ['g2.2xlarge', 'cg1.4xlarge']

CLUSTER_HIMEM_TYPES = ['cr1.8xlarge']

HIMEM_TYPES = ['r3.large', 'r3.xlarge', 'r3.2xlarge', 'r3.4xlarge',
               'r3.8xlarge']

HI_IO_TYPES = ['hi1.4xlarge']

HI_STORAGE_TYPES = ['hs1.8xlarge']

M3_COMPUTE_TYPES = ['c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge',
                    'c3.8xlarge']

I2_STORAGE_TYPES = ['i2.xlarge', 'i2.2xlarge', 'i2.4xlarge', 'i2.8xlarge']

HVM_ONLY_TYPES = (CLUSTER_COMPUTE_TYPES + CLUSTER_GPU_TYPES +
                  CLUSTER_HIMEM_TYPES + I2_STORAGE_TYPES + HIMEM_TYPES +
                  T2_INSTANCE_TYPES)

HVM_TYPES = (HVM_ONLY_TYPES + HI_IO_TYPES + HI_STORAGE_TYPES + SEC_GEN_TYPES +
             M3_COMPUTE_TYPES)

EBS_ONLY_TYPES = T1_INSTANCE_TYPES + T2_INSTANCE_TYPES

# Always make sure these match instances listed here:
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html
# TethysCluster additionally adds cc1.4xlarge to the list - EC2 is slowly
# migrating folks away from this type in favor of cc2.8xlarge but the type
# still works for some older accounts.
PLACEMENT_GROUP_TYPES = (M3_COMPUTE_TYPES + HVM_ONLY_TYPES + HI_IO_TYPES +
                         HI_STORAGE_TYPES + AZURE_INSTANCE_TYPES.keys())
# T2 instances are HVM_ONLY_TYPES however they're not compatible with placement
# groups so remove them from the list
for itype in T2_INSTANCE_TYPES:
    PLACEMENT_GROUP_TYPES.remove(itype)

# Only add a region to this list after testing that you can create and delete a
# placement group there.
PLACEMENT_GROUP_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1',
                           'ap-northeast-1', 'ap-southeast-1',
                           'ap-southeast-2']

AZURE_REGIONS = ['West US', 'Central US', 'East US', 'East US 2',
                 'US Gov Iowa', 'US Gov Virginia', 'North Central US',
                 'South Central US', 'West US', 'North Europe',
                 'West Europe', 'East Asia', 'Southeast Asia',
                 'Japan East', 'Japan West', 'Brazil South',
                 'Australia East', 'Australia Southeast']

PLACEMENT_GROUP_REGIONS.extend(AZURE_REGIONS)



PROTOCOLS = ['tcp', 'udp', 'icmp']

WORLD_CIDRIP = '0.0.0.0/0'

DEFAULT_SSH_PORT = 22
DEFAULT_RDP_PORT = 3389

AVAILABLE_SHELLS = {
    "bash": True,
    "zsh": True,
    "csh": True,
    "ksh": True,
    "tcsh": True,
}

GLOBAL_SETTINGS = {
    # setting, type, required?, default, options, callback
    'default_template': (str, False, None, None, None),
    'enable_experimental': (bool, False, False, None, None),
    'refresh_interval': (int, False, 30, None, None),
    'web_browser': (str, False, None, None, None),
    'include': (list, False, [], None, None),
}

AWS_SETTINGS = {
    'aws_access_key_id': (str, True, None, None, None),
    'aws_secret_access_key': (str, True, None, None, None),
    'aws_user_id': (str, False, None, None, None),
    'ec2_cert': (str, False, None, None, __expand_all),
    'ec2_private_key': (str, False, None, None, __expand_all),
    'aws_port': (int, False, None, None, None),
    'aws_ec2_path': (str, False, '/', None, None),
    'aws_s3_path': (str, False, '/', None, None),
    'aws_is_secure': (bool, False, True, None, None),
    'aws_region_name': (str, False, None, None, None),
    'aws_region_host': (str, False, None, None, None),
    'aws_s3_host': (str, False, None, None, None),
    'aws_proxy': (str, False, None, None, None),
    'aws_proxy_port': (int, False, None, None, None),
    'aws_proxy_user': (str, False, None, None, None),
    'aws_proxy_pass': (str, False, None, None, None),
    'aws_validate_certs': (bool, False, True, None, None),
}

AZURE_SETTINGS = {
    'subscription_id': (str, True, None, None, None),
    'certificate_path': (str, True, None, None, __expand_all),
    # 'azure_cert': (str, False, None, None, __expand_all),
    # 'azure_private_key': (str, False, None, None, __expand_all),
    # 'aws_port': (int, False, None, None, None),
    # 'aws_ec2_path': (str, False, '/', None, None),
    # 'aws_s3_path': (str, False, '/', None, None),
    # 'aws_is_secure': (bool, False, True, None, None),
    # 'aws_region_name': (str, False, None, None, None),
    # 'aws_region_host': (str, False, None, None, None),
    # 'aws_s3_host': (str, False, None, None, None),
    # 'aws_proxy': (str, False, None, None, None),
    # 'aws_proxy_port': (int, False, None, None, None),
    # 'aws_proxy_user': (str, False, None, None, None),
    # 'aws_proxy_pass': (str, False, None, None, None),
    # 'aws_validate_certs': (bool, False, True, None, None),
}

KEY_SETTINGS = {
    'key_location': (str, True, None, None, __expand_all),
}

EBS_VOLUME_SETTINGS = {
    'volume_id': (str, True, None, None, None),
    'device': (str, False, None, None, None),
    'partition': (int, False, None, None, None),
    'mount_path': (str, True, None, None, None),
}

PLUGIN_SETTINGS = {
    'setup_class': (str, True, None, None, None),
}

PERMISSION_SETTINGS = {
    # either you're specifying an ip-based rule
    'ip_protocol': (str, False, 'tcp', PROTOCOLS, None),
    'from_port': (int, True, None, None, None),
    'to_port': (int, True, None, None, None),
    'cidr_ip': (str, False, '0.0.0.0/0', None, None),
    # or you're allowing full access to another security group
    # skip this for now...these two options are mutually exclusive to
    # the four settings above and source_group is  less commonly
    # used. address this when someone requests it.
    # 'source_group': (str, False, None),
    # 'source_group_owner': (int, False, None),
}

CLUSTER_SETTINGS = {
    'cloud_provider': (str, True, CLOUD_PROVIDERS['aws'], None, None),
    'spot_bid': (float, False, None, None, None),
    'cluster_size': (int, True, None, None, None),
    'cluster_user': (str, False, 'tethysadmin', None, None),
    'cluster_shell': (str, False, 'bash', AVAILABLE_SHELLS.keys(), None),
    'subnet_id': (str, False, None, None, None),
    'public_ips': (bool, False, None, None, None),
    'master_image_id': (str, False, None, None, None),
    'master_instance_type': (str, False, None, INSTANCE_TYPES.keys(), None),
    'node_image_id': (str, True, None, None, None),
    'node_instance_type': (list, True, [], None, None),
    'availability_zone': (str, False, None, None, None),
    'keyname': (str, True, None, None, None),
    'extends': (str, False, None, None, None),
    'volumes': (list, False, [], None, None),
    'plugins': (list, False, [], None, None),
    'permissions': (list, False, [], None, None),
    'userdata_scripts': (list, False, [], None, __expand_all_in_list),
    'disable_queue': (bool, False, False, None, None),
    'force_spot_master': (bool, False, False, None, None),
    'disable_cloudinit': (bool, False, False, None, None),
    'dns_prefix': (bool, False, False, None, None),
}
