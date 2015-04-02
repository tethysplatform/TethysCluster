# Copyright 2009-2014 Justin Riley
#
# This file is part of TethysCluster.
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
Azure Utility Classes
"""

import os
import re
import time
import base64
import string
import tempfile

import azure

from tethyscluster import image
from tethyscluster import utils
from tethyscluster import static
from tethyscluster import spinner
from tethyscluster import sshutils
from tethyscluster import webtools
from tethyscluster import exception
from tethyscluster import progressbar
from tethyscluster.utils import print_timing
from tethyscluster.logger import log


class EasyAzure(object):

    def __init__(self, subscription_id, certificate_path,
                 connection_authenticator, **kwargs):
        """
        Create an EasyAzure object.

        Requires aws_access_key_id/aws_secret_access_key from an Amazon Web
        Services (AWS) account and a connection_authenticator function that
        returns an authenticated AWS connection object

        Providing only the keys will default to using Amazon EC2

        kwargs are passed to the connection_authenticator's constructor
        """
        self.subscription_id = subscription_id
        self.certificate_path = certificate_path
        self.connection_authenticator = connection_authenticator
        self._conn = None
        self._kwargs = kwargs

    def reload(self):
        self._conn = None
        return self.conn

    @property
    def conn(self):
        if self._conn is None:
            log.debug('creating self._conn w/ connection_authenticator ' +
                      'kwargs = %s' % self._kwargs)
            # validate_certs = self._kwargs.get('validate_certs', True)
            # if validate_certs:
            #     # if not HAVE_HTTPS_CONNECTION:
            #         raise exception.AWSError(
            #             "Failed to validate AWS SSL certificates. "
            #             "SSL certificate validation is only supported "
            #             "on Python>=2.6.\n\nSet AWS_VALIDATE_CERTS=False in "
            #             "the [aws info] section of your config to skip SSL "
            #             "certificate verification and suppress this error AT "
            #             "YOUR OWN RISK.")
            # if not boto_config.has_section('Boto'):
            #     boto_config.add_section('Boto')
            # # Hack to get around the fact that boto ignores validate_certs
            # # if https_validate_certificates is declared in the boto config
            # boto_config.setbool('Boto', 'https_validate_certificates',
            #                     validate_certs)
            self._conn = self.connection_authenticator(
                self.subscription_id, self.certificate_path,
                **self._kwargs)
            # self._conn.https_validate_certificates = validate_certs
        return self._conn


class EasySMS(EasyAzure):
    def __init__(self, subscription_id, certificate_path,
                 aws_ec2_path='/', aws_s3_host=None, aws_s3_path='/',
                 aws_port=None, aws_region_name=None, aws_is_secure=True,
                 aws_region_host=None, aws_proxy=None, aws_proxy_port=None,
                 aws_proxy_user=None, aws_proxy_pass=None,
                 aws_validate_certs=True, **kwargs):
        azure_region = ''
        kwds = dict(is_secure=aws_is_secure, region=azure_region, port=aws_port,
                    path=aws_ec2_path, proxy=aws_proxy,
                    proxy_port=aws_proxy_port, proxy_user=aws_proxy_user,
                    proxy_pass=aws_proxy_pass,
                    validate_certs=aws_validate_certs)
        super(EasySMS, self).__init__(subscription_id, certificate_path,
                                      azure.servicemanagement.ServiceManagementService, **kwds)

    def __repr__(self):
        raise NotImplementedError()

    def _fetch_account_attrs(self):
        raise NotImplementedError()

    @property
    def supported_platforms(self):
        raise NotImplementedError()

    @property
    def default_vpc(self):
        raise NotImplementedError()

    def connect_to_region(self, region_name):
        raise NotImplementedError()

    @property
    def region(self):
        raise NotImplementedError()

    @property
    def regions(self):
        raise NotImplementedError()

    def get_region(self, region_name):
        raise NotImplementedError()

    def list_regions(self):
        raise NotImplementedError()

    @property
    def registered_images(self):
        raise NotImplementedError()

    @property
    def executable_images(self):
        raise NotImplementedError()

    def get_registered_image(self, image_id):
        raise NotImplementedError()

    def _wait_for_group_deletion_propagation(self, group):
        raise NotImplementedError()

    def get_subnet(self, subnet_id):
        raise NotImplementedError()

    def get_subnets(self, filters=None):
        raise NotImplementedError()

    def get_internet_gateways(self, filters=None):
        raise NotImplementedError()

    def get_route_tables(self, filters=None):
        raise NotImplementedError()

    def get_network_spec(self, *args, **kwargs):
        raise NotImplementedError()

    def get_network_collection(self, *args, **kwargs):
        raise NotImplementedError()

    def delete_group(self, group, max_retries=60, retry_delay=5):
        raise NotImplementedError()

    def create_group(self, name, description, auth_ssh=False, auth_rdp=False,
                     auth_group_traffic=False, vpc_id=None):
        raise NotImplementedError()

    def get_all_security_groups(self, groupnames=[]):
        raise NotImplementedError()

    def get_group_or_none(self, name):
        raise NotImplementedError()

    def get_or_create_group(self, name, description, auth_ssh=True,
                            auth_group_traffic=False, vpc_id=None):
        raise NotImplementedError()

    def get_security_group(self, groupname):
        raise NotImplementedError()

    def get_security_groups(self, filters=None):
        raise NotImplementedError()

    def get_permission_or_none(self, group, ip_protocol, from_port, to_port,
                               cidr_ip=None):
        raise NotImplementedError()

    def has_permission(self, group, ip_protocol, from_port, to_port, cidr_ip):
        raise NotImplementedError()

    def create_placement_group(self, name):
        raise NotImplementedError()

    def get_placement_groups(self, filters=None):
        raise NotImplementedError()

    def get_placement_group(self, groupname=None):
        raise NotImplementedError()

    def get_placement_group_or_none(self, name):
        raise NotImplementedError()

    def get_or_create_placement_group(self, name):
        raise NotImplementedError()

    def request_instances(self, image_id, price=None, instance_type='m1.small',
                          min_count=1, max_count=1, count=1, key_name=None,
                          security_groups=None, security_group_ids=None,
                          launch_group=None,
                          availability_zone_group=None, placement=None,
                          user_data=None, placement_group=None,
                          block_device_map=None, subnet_id=None,
                          network_interfaces=None):
        raise NotImplementedError()

    def request_spot_instances(self, price, image_id, instance_type='m1.small',
                               count=1, launch_group=None, key_name=None,
                               availability_zone_group=None,
                               security_group_ids=None, subnet_id=None,
                               placement=None, placement_group=None,
                               user_data=None, block_device_map=None,
                               network_interfaces=None):
        raise NotImplementedError()

    def _wait_for_propagation(self, obj_ids, fetch_func, id_filter, obj_name,
                              max_retries=60, interval=5):
        raise NotImplementedError()

    def wait_for_propagation(self, instances=None, spot_requests=None,
                             max_retries=60, interval=5):
        raise NotImplementedError()

    def run_instances(self, image_id, instance_type='m1.small', min_count=1,
                      max_count=1, key_name=None, security_groups=None,
                      placement=None, user_data=None, placement_group=None,
                      block_device_map=None, subnet_id=None,
                      network_interfaces=None):
        raise NotImplementedError()

    def create_image(self, instance_id, name, description=None,
                     no_reboot=False):
        raise NotImplementedError()

    def register_image(self, name, description=None, image_location=None,
                       architecture=None, kernel_id=None, ramdisk_id=None,
                       root_device_name=None, block_device_map=None,
                       virtualization_type=None, sriov_net_support=None,
                       snapshot_id=None):
        raise NotImplementedError()

    def delete_keypair(self, name):
        raise NotImplementedError()

    def import_keypair(self, name, rsa_key_file):
        raise NotImplementedError()

    def create_keypair(self, name, output_file=None):
        raise NotImplementedError()

    def get_keypairs(self, filters={}):
        raise NotImplementedError()

    def get_keypair(self, keypair):
        raise NotImplementedError()

    def get_keypair_or_none(self, keypair):
        raise NotImplementedError()

    def __print_header(self, msg):
        raise NotImplementedError()

    def get_image_name(self, img):
        raise NotImplementedError()

    def get_instance_user_data(self, instance_id):
        raise NotImplementedError()

    def get_securityids_from_names(self, groupnames):
        raise NotImplementedError()

    def get_all_instances(self, instance_ids=[], filters={}):
        raise NotImplementedError()

    def get_instance(self, instance_id):
        raise NotImplementedError()

    def is_valid_conn(self):
        raise NotImplementedError()

    def get_all_spot_requests(self, spot_ids=[], filters=None):
        raise NotImplementedError()

    def list_all_spot_instances(self, show_closed=False):
        raise NotImplementedError()

    def show_instance(self, instance):
        raise NotImplementedError()

    def list_all_instances(self, show_terminated=False):
        raise NotImplementedError()

    def list_images(self, images, sort_key=None, reverse=False):
        raise NotImplementedError()

    def list_registered_images(self):
        raise NotImplementedError()

    def list_executable_images(self):
        raise NotImplementedError()

    def __list_images(self, msg, imgs):
        raise NotImplementedError()

    def remove_image_files(self, image_name, pretend=True):
        raise NotImplementedError()

    @print_timing("Removing image")
    def remove_image(self, image_name, pretend=True, keep_image_data=True):
        raise NotImplementedError()

    def list_starcluster_public_images(self):
        raise NotImplementedError()

    def create_volume(self, size, zone, snapshot_id=None):
        raise NotImplementedError()

    def remove_volume(self, volume_id):
        raise NotImplementedError()

    def list_keypairs(self):
        raise NotImplementedError()

    def list_zones(self, region=None):
        raise NotImplementedError()

    def get_zones(self, filters=None):
        raise NotImplementedError()

    def get_zone(self, zone):
        raise NotImplementedError()

    def get_zone_or_none(self, zone):
        raise NotImplementedError()

    def create_s3_image(self, instance_id, key_location, aws_user_id,
                        ec2_cert, ec2_private_key, bucket, image_name="image",
                        description=None, kernel_id=None, ramdisk_id=None,
                        remove_image_files=False, **kwargs):
        raise NotImplementedError()

    def create_ebs_image(self, instance_id, key_location, name,
                         description=None, snapshot_description=None,
                         kernel_id=None, ramdisk_id=None, root_vol_size=15,
                         **kwargs):
        raise NotImplementedError()

    def get_images(self, filters=None):
        raise NotImplementedError()

    def get_image(self, image_id):
        raise NotImplementedError()

    def get_image_or_none(self, image_id):
        raise NotImplementedError()

    def get_image_files(self, image):
        raise NotImplementedError()

    def get_image_bucket(self, image):
        raise NotImplementedError()

    def get_image_manifest(self, image):
        raise NotImplementedError()

    @print_timing("Migrating image")
    def migrate_image(self, image_id, destbucket, migrate_manifest=False,
                      kernel_id=None, ramdisk_id=None, region=None, cert=None,
                      private_key=None):
        raise NotImplementedError()

    def copy_image(self, source_region, source_image_id, name=None,
                   description=None, client_token=None, wait_for_copy=False):
        raise NotImplementedError()

    def wait_for_ami(self, ami):
        raise NotImplementedError()

    def copy_image_to_all_regions(self, source_region, source_image_id,
                                  name=None, description=None,
                                  client_token=None, add_region_to_desc=False,
                                  wait_for_copies=False):
        raise NotImplementedError()

    def create_block_device_map(self, root_snapshot_id=None,
                                root_device_name='/dev/sda1',
                                add_ephemeral_drives=False,
                                num_ephemeral_drives=24, instance_store=False):
        raise NotImplementedError()

    @print_timing("Downloading image")
    def download_image_files(self, image_id, destdir):
        raise NotImplementedError()

    def list_image_files(self, image_id):
        raise NotImplementedError()

    @property
    def instances(self):
        raise NotImplementedError()

    @property
    def keypairs(self):
        raise NotImplementedError()

    def terminate_instances(self, instances=None):
        raise NotImplementedError()

    def get_volumes(self, filters=None):
        raise NotImplementedError()

    def get_volume(self, volume_id):
        raise NotImplementedError()

    def get_volume_or_none(self, volume_id):
        raise NotImplementedError()

    def wait_for_volume(self, volume, status=None, state=None,
                        refresh_interval=5, log_func=log.info):
        raise NotImplementedError()

    def wait_for_snapshot(self, snapshot, refresh_interval=30):
        raise NotImplementedError()

    def create_snapshot(self, vol, description=None, wait_for_snapshot=False,
                        refresh_interval=30):
        raise NotImplementedError()

    def get_snapshots(self, volume_ids=[], filters=None, owner='self'):
        raise NotImplementedError()

    def get_snapshot(self, snapshot_id, owner='self'):
        raise NotImplementedError()

    def list_volumes(self, volume_id=None, status=None, attach_status=None,
                     size=None, zone=None, snapshot_id=None,
                     show_deleted=False, tags=None, name=None):
        raise NotImplementedError()

    def get_spot_history(self, instance_type, start=None, end=None, zone=None,
                         plot=False, plot_server_interface="localhost",
                         plot_launch_browser=True, plot_web_browser=None,
                         plot_shutdown_server=True, classic=False, vpc=False):
        raise NotImplementedError()

    def show_console_output(self, instance_id):
        raise NotImplementedError()


class EasyAzureStorage(EasyAzure):
    DefaultHost = ''

    def __init__(self, aws_access_key_id, certificate_path,
                 aws_s3_path='/', aws_port=None, aws_is_secure=True,
                 aws_s3_host=DefaultHost, aws_proxy=None, aws_proxy_port=None,
                 aws_proxy_user=None, aws_proxy_pass=None,
                 aws_validate_certs=True, **kwargs):
        raise NotImplementedError()

    def __repr__(self):
        raise NotImplementedError()

    def create_bucket(self, bucket_name):
        raise NotImplementedError()

    def bucket_exists(self, bucket_name):
        raise NotImplementedError()

    def get_or_create_bucket(self, bucket_name):
        raise NotImplementedError()

    def get_bucket_or_none(self, bucket_name):
        raise NotImplementedError()

    def get_bucket(self, bucketname):
        raise NotImplementedError()

    def list_bucket(self, bucketname):
        raise NotImplementedError()

    def get_buckets(self):
        raise NotImplementedError()

    def get_bucket_files(self, bucketname):
        raise NotImplementedError()

if __name__ == "__main__":
    # from tethyscluster.config import get_easy_ec2
    # ec2 = get_easy_ec2()
    # ec2.list_all_instances()
    # ec2.list_registered_images()

    from azure import *
    from azure.servicemanagement import *
    from pprint import pprint

    subscription_id = '4477d6f7-b8e4-4bcd-a7ff-c34d1d37238c'
    certificate_path = '/Users/sdc50/.tethyscluster/Azpas300EF16037.pem'

    sms = ServiceManagementService(subscription_id, certificate_path)

    name = 'ci-water-test-vm'
    desc = 'test hosted service'
    location = 'West US'

        # props = sms.get_hosted_service_properties(service.service_name, True)
        # if len(props.deployments) > 0 and len(props.deployments[0].role_list) > 0:
        #     if props.deployments[0].role_list[0].role_type == 'PersistentVMRole':
        #         print(props.deployments[0].role_list[0].role_name)



    services = sms.list_hosted_services()
    # for k,v in services[0].hosted_service_properties.__dict__.iteritems():
    #     print '%s:%s' % (k, v)
    #     """
    #     status:Created
    #     description:
    #     label:BYU-RAPID
    #     location:North Europe
    #     affinity_group:
    #     date_created:2014-10-24T20:28:38Z
    #     extended_properties:{u'ResourceGroup': u'BYU-RAPID', u'ResourceLocation': u'North Europe'}
    #     date_last_modified:2014-10-24T20:29:03Z
    #     """

    services = [sms.get_hosted_service_properties('ciwater-condorm', True), sms.get_hosted_service_properties(name, True)]

    for service in services:
        name = service.service_name
        print('Service name: ' + name)
        print('Management URL: ' + service.url)
        print 'Deployments: ', [[role.__dict__ for role in deployment.role_instance_list.role_instances] for
                                deployment in service.deployments.deployments]
        print('Location: ' + service.hosted_service_properties.location)
        print('Properties: ' + str(service.hosted_service_properties.__dict__))
        print('')


    #Set the location
    # sms.create_hosted_service(service_name=name,
    #     label=name,
    #     description=desc,
    #     location=location)


    images = sms.list_vm_images()
    # for k,v in images[0].__dict__.iteritems():
    #     print '%s:%s' % (k, v)
    #     '''
    #     pricing_detail_link:None
    #     eula:None
    #     deployment_name:ciwater-condorm
    #     service_name:ciwater-condorm
    #     is_premium:False
    #     created_time:2015-01-07T22:45:19.3314472Z
    #     publisher_name:None
    #     category:User
    #     os_disk_configuration:<azure.servicemanagement.OSDiskConfiguration object at 0x103d2d5d0>
    #     icon_uri:None
    #     label:condor-image
    #     show_in_gui:False
    #     location:West US
    #     recommended_vm_size:None
    #     description:None
    #     data_disk_configurations:<azure.servicemanagement.DataDiskConfigurations object at 0x103d2dd10>
    #     image_family:None
    #     modified_time:2015-01-07T22:45:19.3314472Z
    #     role_name:ciwater-condorm
    #     affinity_group:None
    #     privacy_uri:None
    #     name:condor-image
    #     language:None
    #     small_icon_uri:None
    #     published_date:None
    #     Image name: condor-image
    #     Location: West US
    #     '''
    for image in images:
        print('Image name: ' + image.name)
        print('OS: ' + image.os_disk_configuration.os)
        print('Location: ' + image.location)
        print('')


    #'''
    # # Name of an os image as returned by list_os_images
    image_name = 'condor-master' #'b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_10-amd64-server-20150202-en-us-30GB'
    #
    # # Destination storage account container/blob where the VM disk
    # # will be created
    media_link = 'https://ciwater.blob.core.windows.net/vhds/tethys1.tethys1.tethys1.status'
    #
    # # Linux VM configuration, you can use WindowsConfigurationSet
    # # for a Windows VM instead

    # class WindowsConfigurationSet(WindowsAzureData):
    #     def __init__(self, computer_name=None, admin_password=None,
    #                  reset_password_on_first_logon=None,
    #                  enable_automatic_updates=None, time_zone=None,
    #                  admin_username=None, custom_data=None):
    #
    # class LinuxConfigurationSet(WindowsAzureData):
    # def __init__(self, host_name=None, user_name=None, user_password=None,
    #              disable_ssh_password_authentication=None, custom_data=None):

    host_name = 'master'
    user_name='tethysadmin'
    password = 'TA(|w@ter'

    linux_config = LinuxConfigurationSet('master', 'tethysadmin', 'TA(|w@ter')
    windows_config = WindowsConfigurationSet(host_name, password, False, True, None, user_name, None)
    windows_config.domain_join = None #I don't know what this does or why it is needed
    windows_config.win_rm = None #I don't know what this does or why it is needed

    #
    os_hd = OSVirtualHardDisk(image_name, media_link)
    #from OS Image
    # sms.create_virtual_machine_deployment(service_name=name,
    #     deployment_name=name,
    #     deployment_slot='production',
    #     label=name,
    #     role_name=name,
    #     system_config=linux_config,
    #     os_virtual_hard_disk=os_hd,
    #     role_size='Small')

    #from VM image
    # sms.create_virtual_machine_deployment(service_name=name,
    # deployment_name=name,
    # deployment_slot='production',
    # label=name,
    # role_name=name,
    # system_config=windows_config,
    # os_virtual_hard_disk=None,
    # role_size='Small',
    # vm_image_name = image_name)
    #'''