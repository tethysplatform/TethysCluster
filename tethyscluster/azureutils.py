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

from azure import *
from azure.servicemanagement import *
from pprint import pprint

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
                 host=None, request_session=None, location='West US', **kwargs):
        kwds = dict(request_session=request_session)
        super(EasySMS, self).__init__(subscription_id, certificate_path,
                                      azure.servicemanagement.ServiceManagementService, **kwds)
        self._conn = kwargs.get('connection')
        # kwds = dict(aws_s3_host=aws_s3_host, aws_s3_path=aws_s3_path,
        #             aws_port=aws_port, aws_is_secure=aws_is_secure,
        #             aws_proxy=aws_proxy, aws_proxy_port=aws_proxy_port,
        #             aws_proxy_user=aws_proxy_user,
        #             aws_proxy_pass=aws_proxy_pass,
        #             aws_validate_certs=aws_validate_certs)
        # self.s3 = EasyS3(aws_access_key_id, aws_secret_access_key, **kwds)
        self._regions = None
        self._region = self.get_region(location)
        self._account_attrs = None
        self._account_attrs_region = None

    def __repr__(self):
        return '<EasySMS: %s (%s)>' % (self.region.name, ' '.join(self.region.available_services))

    def _fetch_account_attrs(self):
        raise NotImplementedError()

    @property
    def supported_platforms(self):
        raise NotImplementedError()

    @property
    def default_vpc(self):
        raise NotImplementedError()

    def connect_to_region(self, region_name):
        """
        Connects to a given region if it exists, raises RegionDoesNotExist
        otherwise. Once connected, this object will return only data from the
        given region.
        """
        self._region = self.get_region(region_name)
        self._platforms = None
        self._default_vpc = None
        self.reload()
        return self

    @property
    def region(self):
        """
        Returns the current EC2 region used by this EasyEC2 object
        """
        return self._region

    @property
    def regions(self):
        """
        This property returns all Azure Locations, caching the results the first
        time a request is made to Azure
        """
        if not self._regions:
            self._regions = {}
            regions = self.conn.list_locations()
            for region in regions:
                self._regions[region.name] = region
        return self._regions

    def get_region(self, region_name):
        """
        Returns Azure Location object if it exists, raises RegionDoesNotExist
        otherwise.
        """
        if region_name not in self.regions:
            raise exception.RegionDoesNotExist(region_name)
        return self.regions.get(region_name)

    def list_regions(self):
        """
        Print name/services for all Azure locations
        """
        regions = self.regions.items()
        regions.sort(reverse=True)
        for name, region in regions:
            print 'name: ', name
            print 'services: ', ', '.join(region.available_services)
            print

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

    def get_all_hosted_services(self):
        services = []
        hosted_services = self.conn.list_hosted_services()
        for service in hosted_services:
            services.append(service.service_name)
        return services


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
        """
        Convenience method for running spot or flat-rate instances
        """
        if not block_device_map:
            img = self.get_image(image_id)
            instance_store = img.root_device_type == 'instance-store'
            if instance_type == 'm1.small' and img.architecture == "i386":
                # Needed for m1.small + 32bit AMI (see gh-329)
                instance_store = True
            use_ephemeral = instance_type != 't1.micro'
            bdmap = self.create_block_device_map(
                add_ephemeral_drives=use_ephemeral,
                num_ephemeral_drives=24,
                instance_store=instance_store)
            # Prune drives from runtime block device map that may override EBS
            # volumes specified in the AMIs block device map
            for dev in img.block_device_mapping:
                bdt = img.block_device_mapping.get(dev)
                if not bdt.ephemeral_name and dev in bdmap:
                    log.debug("EBS volume already mapped to %s by AMI" % dev)
                    log.debug("Removing %s from runtime block device map" %
                              dev)
                    bdmap.pop(dev)
            if img.root_device_name in img.block_device_mapping:
                log.debug("Forcing delete_on_termination for AMI: %s" % img.id)
                root = img.block_device_mapping[img.root_device_name]
                # specifying the AMI's snapshot in the custom block device
                # mapping when you dont own the AMI causes an error on launch
                root.snapshot_id = None
                root.delete_on_termination = True
                # AWS API doesn't support any value for this flag for the root
                # device of a new instance (see: boto#2587)
                if hasattr(root, 'encrypted'):
                    root.encrypted = None
                bdmap[img.root_device_name] = root
            block_device_map = bdmap
        shared_kwargs = dict(instance_type=instance_type,
                             key_name=key_name,
                             subnet_id=subnet_id,
                             placement=placement,
                             placement_group=placement_group,
                             user_data=user_data,
                             block_device_map=block_device_map,
                             network_interfaces=network_interfaces)
        if price:
            return self.request_spot_instances(
                price, image_id,
                count=count, launch_group=launch_group,
                security_group_ids=security_group_ids,
                availability_zone_group=availability_zone_group,
                **shared_kwargs)
        else:
            return self.run_instances(
                image_id,
                min_count=min_count, max_count=max_count,
                security_groups=security_groups,
                **shared_kwargs)

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

    def run_instances(self, image_id, aliases=None, service_name=None, instance_type='Small', key_name=None,
                      security_groups=None, user_data=None):

        user_name='tethysadmin'
        password = '@tc-tethysadmin1'


        # start = time.time()
        # image = self.conn.list_vm_images(filters={'label':image_id})[0]
        # print time.time()-start
        # start = time.time()
        images = self.conn.list_vm_images()
        image = None
        for i in images:
            if i.name == image_id:
                image = i
        # print time.time()-start
        os = image.os_disk_configuration.os
        if os =='Windows':
            hostname = 'computer_name'
            system_config = WindowsConfigurationSet(admin_password=password,
                                                     reset_password_on_first_logon=False,
                                                     enable_automatic_updates=True,
                                                     time_zone=None,
                                                     admin_username=user_name,
                                                     custom_data=user_data)
            system_config.domain_join = None #I don't know what this does or why it is needed
            system_config.win_rm = None #I don't know what this does or why it is needed
        elif os == 'Linux':
            hostname = 'host_name'
            system_config = LinuxConfigurationSet(user_name=user_name,
                                                  user_password=password,
                                                  disable_ssh_password_authentication=False,
                                                  custom_data=user_data)
        else:
            raise Exception('%s is not a supported os' % (os,))

        def get_endpoints(rdp_port, ssh_port):
            endpoint_config = ConfigurationSet()
            endpoint_config.configuration_set_type = 'NetworkConfiguration'

            endpoint1 = ConfigurationSetInputEndpoint(name = 'rdp',
                                                      protocol = 'tcp',
                                                      port = rdp_port,
                                                      local_port = '3389',
                                                      load_balanced_endpoint_set_name = None,
                                                      enable_direct_server_return = False)
            endpoint2 = ConfigurationSetInputEndpoint(name = 'ssh',
                                                      protocol = 'tcp',
                                                      port = ssh_port,
                                                      local_port = '22',
                                                      load_balanced_endpoint_set_name = None,
                                                      enable_direct_server_return = False)

            #endpoints must be specified as elements in a list

            endpoint_config.input_endpoints.input_endpoints.append(endpoint1)
            endpoint_config.input_endpoints.input_endpoints.append(endpoint2)
            return endpoint_config


        for alias in aliases:
            print alias
            rdp_port = 3389
            ssh_port = 22
            alias_parts = re.split('node', alias)
            if len(alias_parts) == 2:
                index = alias_parts[1]
                rdp_port = '33' + index
                ssh_port = '22' + index
            system_config.__dict__[hostname] = alias
            kwargs = dict(service_name=service_name,
                          deployment_name=service_name,
                          role_name=alias,
                          system_config=system_config,
                          os_virtual_hard_disk=None,
                          network_config = get_endpoints(rdp_port, ssh_port),
                          role_size=instance_type,
                          vm_image_name = image_id,
                          )

            try:
                deployment = self.conn.get_deployment_by_name(service_name, service_name)
            except WindowsAzureMissingResourceError as e:
                deployment = None
            if not deployment:
                 id = self.conn.create_virtual_machine_deployment(deployment_slot='production', label=alias,
                                                                  **kwargs).request_id
            else:
                id = self.conn.add_role(**kwargs).request_id
            self.conn.wait_for_operation_status(id, timeout=60)

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
        hosted_services = self.get_all_hosted_services()
        instances = []
        roles = []
        for name in hosted_services:
            service = self.conn.get_hosted_service_properties(name, True)
            for deployment in service.deployments.deployments:
                instances.extend(deployment.role_instance_list.role_instances)
                roles.extend(deployment.role_list.roles)
            # insts = [role for role in [deployment.role_instance_list.role_instances for
            #                     deployment in service.deployments.deployments]]

        # pprint(instances[0].__dict__)
        # pprint(roles[0].__dict__)

        return instances

            # props = sms.get_hosted_service_properties(service.service_name, True)
            # if len(props.deployments) > 0 and len(props.deployments[0].role_list) > 0:
            #     if props.deployments[0].role_list[0].role_type == 'PersistentVMRole':
            #         print(props.deployments[0].role_list[0].role_name)

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

    import unittest

    class TestAzureUtils(unittest.TestCase):

        subscription_id = '4477d6f7-b8e4-4bcd-a7ff-c34d1d37238c'
        certificate_path = '/Users/sdc50/.tethyscluster/Azpas300EF16037.pem'

        easySMS = EasySMS(subscription_id, certificate_path, location = 'West US')

        def test_regions(self):
            # print self.easySMS.list_regions()
            # print self.easySMS.region.name
            region = 'West US'
            self.easySMS.connect_to_region(region)
            expected = region
            actual = self.easySMS.region.name
            msg = 'checking region gets set properly'
            self.assertEqual(expected, actual, '%s\nExpected: %s\nActual:   %s\n' % (msg, expected, actual))

        def test_invalid_region(self):
            method = self.easySMS.connect_to_region
            args = ('Invalid Region')
            self.assertRaises(exception.RegionDoesNotExist, method, args)

        '''
        def run_instance(self):
            '''
        def test_run_instances(self):
        #'''
            # subscription = self.easySMS.conn.list_subscriptions()[0]
            service_name = 'tc-test-cluster-%s' % (self.subscription_id,)
            service_desc = 'TethysCluster-%s' % static.VERSION.replace('.', '_')
            available = self.easySMS.conn.check_hosted_service_name_availability(service_name).result
            if available:
                service = self.easySMS.conn.create_hosted_service(service_name=service_name,
                    label=service_name,
                    description=service_desc,
                    location=self.easySMS.region.name)
            else:
                print 'hosted service already exists'
            service = self.easySMS.conn.get_hosted_service_properties(service_name, True)

            master_alias = 'master'
            image_id = 'tc-linux12-0'

            # id = self.easySMS.run_instances(image_id, master_alias, service_name).request_id
            # print id
            # self.easySMS.conn.wait_for_operation_status(id)
            aliases = [master_alias]
            for node in range(1,2):
                alias = 'node00%s' % (node,)
                aliases.append(alias)
                # id = self.easySMS.run_instances(image_id, alias, service_name).request_id
                # self.easySMS.conn.wait_for_operation_status(id)
            self.easySMS.run_instances(image_id, aliases, service_name)

            pprint(service.hosted_service_properties.__dict__)
            print service.deployments.deployments


        def test_get_all_instances(self):
            instances = self.easySMS.get_all_instances()
            print [instance.role_name for instance in instances]

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAzureUtils)
    unittest.TextTestRunner(verbosity=2).run(suite)









    # sms = ServiceManagementService(subscription_id, certificate_path)

    # pprint(sms.__dict__)
    # '''
    # {'_filter': <bound method _HTTPClient.perform_request of <azure.http.httpclient._HTTPClient object at 0x1034486d0>>,
    #  '_httpclient': <azure.http.httpclient._HTTPClient object at 0x1034486d0>,
    #  'cert_file': '/Users/sdc50/.tethyscluster/Azpas300EF16037.pem',
    #  'content_type': 'application/atom+xml;type=entry;charset=utf-8',
    #  'host': 'management.core.windows.net',
    #  'request_session': None,
    #  'requestid': None,
    #  'subscription_id': '4477d6f7-b8e4-4bcd-a7ff-c34d1d37238c',
    #  'x_ms_version': '2014-06-01'}
    # '''


    # services = sms.list_hosted_services()
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

    # services = [sms.get_hosted_service_properties('ciwater-condorm', True), sms.get_hosted_service_properties(name, True)]
    #
    # for service in services:
    #     name = service.service_name
    #     print('Service name: ' + name)
    #     print('Management URL: ' + service.url)
    #     print 'Deployments: ', [[role.__dict__ for role in deployment.role_instance_list.role_instances] for
    #                             deployment in service.deployments.deployments]
    #     print('Location: ' + service.hosted_service_properties.location)
    #     print('Properties: ' + str(service.hosted_service_properties.__dict__))
    #     print('')


    # images = sms.list_vm_images()
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
    # for image in images:
    #     print('Image name: ' + image.name)
    #     print('OS: ' + image.os_disk_configuration.os)
    #     print('Location: ' + image.location)
    #     print('')


    #'''
    # # Name of an os image as returned by list_os_images
    # image_name = 'b39f27a8b8c64d52b05eac6a62ebad85__Ubuntu-14_10-amd64-server-20150202-en-us-30GB'
    # media_link = 'https://ciwater.blob.core.windows.net/vhds/tethys1.tethys1.tethys1.status'

    # os_hd = OSVirtualHardDisk(image_name, media_link)
    #from OS Image
    # sms.create_virtual_machine_deployment(service_name=name,
    #     deployment_name=name,
    #     deployment_slot='production',
    #     label=name,
    #     role_name=name,
    #     system_config=linux_config,
    #     os_virtual_hard_disk=os_hd,
    #     role_size='Small')

    #'''