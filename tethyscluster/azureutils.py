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
import fnmatch

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
        self._subscription_name = None
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

    @property
    def subscription_name(self):
        if not self._subscription_name:
            subscription_name = self.conn.get_subscription().subscription_name
            self._subscription_name = subscription_name
        return self._subscription_name

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
        """
        This method deletes a security or placement group using group.delete()
        but in the case that group.delete() throws a DependencyViolation error
        or InvalidPlacementGroup.InUse error it will keep retrying until it's
        successful. Waits 5 seconds between each retry.
        """
        if isinstance(group, SecurityGroup):
            label = 'security'
        elif isinstance(group, PlacementGroup):
            label = 'placement'
        s = utils.get_spinner("Removing %s group: %s" % (label, group.name))
        try:
            for i in range(max_retries):
                try:
                    self.conn.delete_hosted_service(group.id)
                    return
                except azure.WindowsAzureError as e:
                    if i == max_retries - 1:
                        raise
                    # if e.error_code == 'DependencyViolation':
                    #     log.debug('DependencyViolation error - retrying in 5s',
                    #               exc_info=True)
                    #     time.sleep(retry_delay)
                    # elif e.error_code == 'InvalidPlacementGroup.InUse':
                    #     log.debug('Placement group in use - retrying in 5s',
                    #               exc_info=True)
                    #     time.sleep(retry_delay)
                    else:
                        raise
        finally:
            s.stop()

    def create_group(self, name, description, auth_ssh=False, auth_rdp=False,
                     auth_group_traffic=False, vpc_id=None):
        """
        Create security group with name/description. auth_ssh=True
        will open port 22 to world (0.0.0.0/0). auth_group_traffic
        will allow all traffic between instances in the same security
        group
        """
        log.info("Creating security group %s..." % name)
        # sg = self.conn.create_security_group(name, description, vpc_id=vpc_id)
        # if not self.get_group_or_none(name):
        #     s = utils.get_spinner("Waiting for security group %s..." % name)
        #     try:
        #         while not self.get_group_or_none(name):
        #             time.sleep(3)
        #     finally:
        #         s.stop()
        # if auth_ssh:
        #     ssh_port = static.DEFAULT_SSH_PORT
        #     sg.authorize(ip_protocol='tcp', from_port=ssh_port,
        #                  to_port=ssh_port, cidr_ip=static.WORLD_CIDRIP)
        # if auth_rdp:
        #     rdp_port = static.DEFAULT_RDP_PORT
        #     sg.authorize(ip_protocol='tcp', from_port=rdp_port,
        #                  to_port=rdp_port, cidr_ip=static.WORLD_CIDRIP)
        # if auth_group_traffic:
        #     sg.authorize(src_group=sg, ip_protocol='icmp', from_port=-1,
        #                  to_port=-1)
        #     sg.authorize(src_group=sg, ip_protocol='tcp', from_port=1,
        #                  to_port=65535)
        #     sg.authorize(src_group=sg, ip_protocol='udp', from_port=1,
        #                  to_port=65535)
        # return sg
        pg = self.get_or_create_placement_group(name)
        if not pg:
            raise exception.PlacementGroupDoesNotExist(name)
        sg = SecurityGroup(pg, self)
        return sg

    def get_all_security_groups(self, groupnames=[]):
        """
        Returns all security groups

        groupnames - optional list of group names to retrieve
        """
        filters = {}
        if groupnames:
            filters = {'group-name': groupnames}
        return self.get_security_groups(filters=filters)

    def get_group_or_none(self, name):
        """
        Returns group with name if it exists otherwise returns None
        """
        try:
            return self.get_security_group(name)
        except exception.SecurityGroupDoesNotExist:
            pass

    def get_or_create_group(self, name, description, auth_ssh=True,
                            auth_group_traffic=False, vpc_id=None):
        """
        Try to return a security group by name. If the group is not found,
        attempt to create it.  Description only applies to creation.

        auth_ssh - authorize ssh traffic from world
        auth_group_traffic - authorizes all traffic between members of the
                             group
        """
        sg = self.get_group_or_none(name)
        if not sg:
            sg = self.create_group(name, description, auth_ssh=auth_ssh,
                                   auth_group_traffic=auth_group_traffic,
                                   vpc_id=vpc_id)
        return sg

    def get_security_group(self, groupname):
        try:
            return self.get_security_groups(
                filters={'group-name': groupname})[0]
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidGroup.NotFound":
            #     raise exception.SecurityGroupDoesNotExist(groupname)
            raise
        except IndexError:
            raise exception.SecurityGroupDoesNotExist(groupname)

    def get_security_groups(self, filters=None):
        """
        Returns all security groups on this cloud account
        """
        #return self.conn.get_all_security_groups(filters=filters)
        pgs =  self.get_placement_groups(filters)
        sgs = [SecurityGroup(pg, self) for pg in pgs]
        return sgs


    def get_permission_or_none(self, group, ip_protocol, from_port, to_port,
                               cidr_ip=None):
        raise NotImplementedError()

    def has_permission(self, group, ip_protocol, from_port, to_port, cidr_ip):
        raise NotImplementedError()

    def _azurify(self, name):
        return '%s-%s' % (name.strip('@').replace('_', '-'), self.subscription_name)

    @classmethod
    def _unazurify(self, name):
        return '@tc-%s' % ('_'.join(name.split('-')[1:-1])) #TODO this will not restore '-' if it was originally present

    def create_placement_group(self, name):
        """
        Create a new placement group for your account.
        This will create the placement group within the region you
        are currently connected to.
        """
        log.info("Creating placement group %s..." % name)
        # success = self.conn.create_placement_group(name)
        # if not success:
        #     log.debug(
        #         "failed to create placement group '%s' (error = %s)" %
        #         (name, success))
        #     raise exception.AWSError(
        #         "failed to create placement group '%s'" % name)
        # pg = self.get_placement_group_or_none(name)
        # while not pg:
        #     log.info("Waiting for placement group %s..." % name)
        #     time.sleep(3)
        #     pg = self.get_placement_group_or_none(name)
        # return pg

        name = self._azurify(name)
        available = self.conn.check_hosted_service_name_availability(name).result
        if available:
            self.conn.create_hosted_service(service_name=name,
                label=name,
                description='TethysCluster-%s' % static.VERSION.replace('.', '_'),
                location=self.region.name)

            service = self.conn.get_hosted_service_properties(name)
            pg = PlacementGroup(service, self)
            return pg
        else:
            raise azure.WindowsAzureError('Hosted Service already exists')

    def get_placement_groups(self, filters=None):
        """
        Returns all hosted services
        """
        #return self.conn.get_all_placement_groups(filters=filters)
        hosted_services = self.list_all_hosted_services()
        group_names = filters['group-name']
        group_names = group_names if isinstance(group_names, list) else [group_names]
        group_names = [self._azurify(name) for name in group_names]
        #'''
        def match(name, filters):
            for filter in filters:
                if fnmatch.fnmatch(name, filter):
                    return True
            return False
        services = [self.conn.get_hosted_service_properties(service_name) for service_name in hosted_services if
                    match(service_name, group_names)]
        '''
        services = []
        for group_name in group_names:
            srvs = fnmatch.filter(hosted_services, group_name)
            services.extend([self.conn.get_hosted_service_properties(service_name) for service_name in srvs])
        #'''
        pgs = [PlacementGroup(service, self) for service in services]
        return pgs

    def get_placement_group(self, groupname=None):
        try:
            return self.get_placement_groups(filters={'group-name':
                                                      groupname})[0]
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidPlacementGroup.Unknown":
            #     raise exception.PlacementGroupDoesNotExist(groupname)
            raise
        except IndexError:
            raise exception.PlacementGroupDoesNotExist(groupname)

    def get_placement_group_or_none(self, name):
        """
        Returns placement group with name if it exists otherwise returns None
        """
        try:
            return self.get_placement_group(name)
        except exception.PlacementGroupDoesNotExist:
            pass

    def get_or_create_placement_group(self, name):
        """
        Try to return a placement group by name.
        If the group is not found, attempt to create it.
        """
        try:
            return self.get_placement_group(name)
        except exception.PlacementGroupDoesNotExist:
            pg = self.create_placement_group(name)
            return pg

    def list_all_hosted_services(self):
        services = []
        hosted_services = self.conn.list_hosted_services()
        for service in hosted_services:
            services.append(service.service_name)
        return services

    def request_instances(self, image_id, price=None, instance_type='Small',
                          min_count=1, max_count=1, count=1, key_name=None,
                          security_groups=None, security_group_ids=None,
                          launch_group=None,
                          availability_zone_group=None, placement=None,
                          user_data=None, placement_group=None,
                          block_device_map=None, subnet_id=None,
                          network_interfaces=None, **kwargs):
        """
        Convenience method for running spot or flat-rate instances
        """
        #I just deleted a bunch of code that handled block device maps. I'm not sure how this applies in Azure

        # kwargs = dict(min_count=min_count,
        #               max_count=max_count,
        #               security_groups=security_groups,
        #               instance_type=instance_type,
        #               key_name=key_name,
        #               subnet_id=subnet_id,
        #               placement=placement,
        #               placement_group=placement_group,
        #               user_data=user_data,
        #               block_device_map=block_device_map,
        #               network_interfaces=network_interfaces)

        kwargs = dict(aliases=kwargs['aliases'], #TODO can I get the aliases from binary user_data?
                      placement_group=self._azurify(placement_group),
                      instance_type=instance_type,
                      key_name=key_name,
                      user_data=user_data)

        instances = self.run_instances(image_id, **kwargs)
        return Reservation(instances)

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
        """
        Wait for a list of object ids to appear in the Azure API. Requires a
        function that fetches the objects and also takes a filters kwarg. The
        id_filter specifies the id filter to use for the objects and
        obj_name describes the objects for log messages.
        """
        filters = {id_filter: obj_ids}
        num_objs = len(obj_ids)
        num_reqs = 0
        reqs_ids = []
        max_retries = max(1, max_retries)
        interval = max(1, interval)
        widgets = ['', progressbar.Fraction(), ' ',
                   progressbar.Bar(marker=progressbar.RotatingMarker()), ' ',
                   progressbar.Percentage(), ' ', ' ']
        log.info("Waiting for %s to propagate..." % obj_name)
        pbar = progressbar.ProgressBar(widgets=widgets,
                                       maxval=num_objs).start()
        try:
            for i in range(max_retries + 1):
                reqs = fetch_func(filters=filters)
                reqs_ids = [req.id for req in reqs]
                num_reqs = len(reqs)
                pbar.update(num_reqs)
                if num_reqs != num_objs:
                    log.debug("%d: only %d/%d %s have "
                              "propagated - sleeping..." %
                              (i, num_reqs, num_objs, obj_name))
                    if i != max_retries:
                        time.sleep(interval)
                else:
                    return
        finally:
            if not pbar.finished:
                pbar.finish()
        missing = [oid for oid in obj_ids if oid not in reqs_ids]
        raise exception.PropagationException(
            "Failed to fetch %d/%d %s after %d seconds: %s" %
            (num_reqs, num_objs, obj_name, max_retries * interval,
             ', '.join(missing)))

    def wait_for_propagation(self, instances=None, spot_requests=None,
                             max_retries=60, interval=5):
        """
        Wait for newly created instances to register in
        the Azure API by repeatedly calling get_all_instances.
        Calling this method directly after creating new instances or spot
        requests before operating on them helps to avoid eventual consistency
        errors about instances not existing.
        """
        if instances:
            instance_ids = [getattr(i, 'id', i) for i in instances]
            self._wait_for_propagation(
                instance_ids, self.get_all_instances, 'instance-id',
                'instances', max_retries=max_retries, interval=interval)

    def run_instances(self, image_id, aliases=None, placement_group=None, instance_type='Small', key_name=None,
                      security_groups=None, user_data=None, **kwargs):

        def add_key_to_service(service_name, key_name):
            from tethyscluster import config
            SERVICE_CERT_FORMAT = 'pfx'
            cfg = config.get_config()
            key_location = cfg.get_key(key_name).get('key_location')
            cert = sshutils.get_or_generate_signed_certificate_from_key(key_location)
            service_cert_file_data = sshutils.get_64base_encoded_certificate(cert)
            fingerprint = sshutils.get_certificate_fingerprint(cert)

            result = self.conn.add_service_certificate(service_name,
                                 service_cert_file_data, SERVICE_CERT_FORMAT, '')

            self.conn.wait_for_operation_status(result.request_id,
                                                timeout=300,
                                                progress_callback=lambda x: sys.stdout.write(''),
                                                success_callback=lambda x: sys.stdout.write(''))

            properties = self.conn.get_hosted_service_properties(service_name, True).hosted_service_properties
            properties.extended_properties['key_name'] = key_name
            self.conn.update_hosted_service(service_name, properties.label, properties.description,
                                                   properties.extended_properties)
            return fingerprint, key_location

        def get_endpoints(rdp_port, ssh_port):
            endpoint_config = ConfigurationSet()
            endpoint_config.configuration_set_type = 'NetworkConfiguration'

            endpoint1 = ConfigurationSetInputEndpoint(name='rdp',
                                                      protocol='tcp',
                                                      port=rdp_port,
                                                      local_port='3389',
                                                      load_balanced_endpoint_set_name=None,
                                                      enable_direct_server_return=False)
            endpoint2 = ConfigurationSetInputEndpoint(name='ssh',
                                                      protocol='tcp',
                                                      port=ssh_port,
                                                      local_port='22',
                                                      load_balanced_endpoint_set_name=None,
                                                      enable_direct_server_return=False)

            #endpoints must be specified as elements in a list

            endpoint_config.input_endpoints.input_endpoints.append(endpoint1)
            endpoint_config.input_endpoints.input_endpoints.append(endpoint2)
            return endpoint_config

        user_name='tethysadmin'
        password = '@tc-tethysadmin1'

        image = self.get_image(image_id)
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
            password = None
            system_config = LinuxConfigurationSet(user_name=user_name,
                                                  user_password=password,
                                                  disable_ssh_password_authentication=False,
                                                  custom_data=user_data)
            if key_name:
                fingerprint, key_location = add_key_to_service(placement_group, key_name)

                thumbprint = fingerprint.replace(':', '')
                ssh = SSH()
                public_key = PublicKey(thumbprint, key_location)
                key_pairs = KeyPair(thumbprint, key_location)
                ssh.public_keys.public_keys.append(public_key)
                ssh.key_pairs.key_pairs.append(key_pairs)
                system_config.ssh = ssh
        else:
            raise Exception('%s is not a supported os' % (os,))


        from userdata import unbundle_userdata
        user_data = unbundle_userdata(user_data)

        aliases = user_data['_tc_aliases.txt'].split('\n')[-2:]

        for alias in aliases:
            # print alias
            ssh_port = static.DEFAULT_SSH_PORT
            rdp_port = static.DEFAULT_RDP_PORT
            alias_parts = re.split('node', alias)
            if len(alias_parts) == 2:
                index = alias_parts[1]
                rdp_port = '33' + index
                ssh_port = str(ssh_port) + index
            system_config.__dict__[hostname] = alias
            kwargs = dict(service_name=placement_group,
                          deployment_name=placement_group,
                          role_name=alias,
                          system_config=system_config,
                          os_virtual_hard_disk=None,
                          network_config=get_endpoints(rdp_port, ssh_port),
                          role_size=instance_type,
                          vm_image_name=image_id,
                          )

            try:
                deployment = self.conn.get_deployment_by_name(placement_group, placement_group)
            except WindowsAzureMissingResourceError as e:
                deployment = None
            if not deployment:
                 result = self.conn.create_virtual_machine_deployment(deployment_slot='production',
                                                                      label=alias, **kwargs)
            else:
                result = self.conn.add_role(**kwargs)
            self.conn.wait_for_operation_status(result.request_id,
                                                timeout=300,
                                                progress_callback=lambda x: sys.stdout.write(''),
                                                success_callback=lambda x: sys.stdout.write(''))

        ids = [(placement_group, placement_group, alias) for alias in aliases]
        return self.get_all_instances(instance_ids=ids,
                                      filters={'instance.group-name': self._unazurify(placement_group)})

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
        certs = self.conn.list_management_certificates().subscription_certificates
        for cert in certs:
            cert.fingerprint = cert.subscription_certificate_thumbprint

        if 'key-name' in filters.keys():
            certs = [cert for cert in certs if cert.fingerprint == filters['key-name']]
        return certs

    def get_keypair(self, keypair):
        try:
            return self.get_keypairs(filters={'key-name': keypair})[0]
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidKeyPair.NotFound":
            #     raise exception.KeyPairDoesNotExist(keypair)
            raise
        except IndexError:
            raise exception.KeyPairDoesNotExist(keypair)

    def get_keypair_or_none(self, keypair):
        try:
            return self.get_keypair(keypair)
        except exception.KeyPairDoesNotExist:
            pass

    def __print_header(self, msg):
        raise NotImplementedError()

    def get_image_name(self, img):
        raise NotImplementedError()

    def get_instance_user_data(self, instance_id):
        try:
            from tethyscluster import config
            # attrs = self.conn.get_instance_attribute(instance_id, 'userData')
            # user_data = attrs.get('userData', '') or ''
            instance = self.get_instance(instance_id)
            cfg = config.get_config()
            key_location = cfg.get_key(instance.key_name).get('key_location')
            ssh = sshutils.SSHClient(instance.ip_address,
                                       username='root',
                                       port = instance.ports['ssh'],
                                       private_key=key_location)
            user_data_file = ssh.remote_file('/var/lib/waagent/ovf-env.xml', 'r')
            text = user_data_file.read()
            match = re.search('<CustomData>(.*?)</CustomData>', text)
            raw = match.group(1)
            user_data = base64.b64decode(raw)
            return user_data
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidInstanceID.NotFound":
            #     raise exception.InstanceDoesNotExist(instance_id)
            raise e
        except Exception, e:
            raise e

    def get_securityids_from_names(self, groupnames):
        raise NotImplementedError()

    def get_all_instances(self, instance_ids=[], filters={}):
        if 'instance.group-name' in filters.keys():
            hosted_services = [self._azurify(filters['instance.group-name'])]
        else:
            hosted_services = self.list_all_hosted_services()
        instances = []
        for name in hosted_services:
            try:
                service = self.conn.get_hosted_service_properties(name, True)
                for deployment in service.deployments.deployments:

                    insts = deployment.role_instance_list.role_instances
                    rols = deployment.role_list.roles
                    assert len(insts) == len(rols)
                    for i in range(0,len(insts)):
                        role = rols[i]
                        if role.role_type == 'PersistentVMRole':
                            instance = Instance(service, deployment, insts[i], role, self)
                            instances.append(instance)
            except WindowsAzureMissingResourceError as e:
                pass


        if instance_ids:
            instances = [instance for instance in instances if instance.id in instance_ids]
        if filters:
            # filters = {'instance-state-name': states,
            #        'instance.group-name': self._security_group}
            if 'instance-state-name' in filters.keys():
                states = filters['instance-state-name']
                states = states if isinstance(states, list) else [states]
                instances = [instance for instance in instances if instance.state in states]
            if 'instance-id' in filters.keys():
                instance_ids = filters['instance-id']
                instance_ids = instance_ids if isinstance(instance_ids, list) else [instance_ids]
                instances = [instance for instance in instances if instance.id in instance_ids]

        return instances

    def get_instance(self, instance_id):
        try:
            return self.get_all_instances(
                filters={'instance-id': instance_id})[0]
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidInstanceID.NotFound":
            #     raise exception.InstanceDoesNotExist(instance_id)
            raise
        except IndexError:
            raise exception.InstanceDoesNotExist(instance_id)

    def is_valid_conn(self):
        try:
            self.get_all_instances()
            return True
        except azure.WindowsAzureError as e:
            cred_errs = [] #add error codes for Azure authorization errors here
            # if e.error_code in cred_errs:
            #     return False
            raise

    def get_all_spot_requests(self, spot_ids=[], filters=None):
        return []

    def list_all_spot_instances(self, show_closed=False):
        log.info("No spot instance requests found...")
        return

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
        return None

    def get_zone_or_none(self, zone):
        return None

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
        # start = time.time()
        # image = self.conn.list_vm_images(filters={'name':image_id})[0]
        # print time.time()-start
        # start = time.time()
        image_id = filters['image-id']
        all_images = self.conn.list_vm_images()
        images = []
        for image in all_images:
            if image.name == image_id:
                image.id = image.name
                image.state = 'available' #required for cluster validation. Are Azure images ever not available?
                image.architecture = 'x86_64'
                image.virtualization_type = None
                image.root_device_type = None
                images.append(image)
        # print time.time()-start
        return images

    def get_image(self, image_id):
        """
        Return image object representing an AMI.
        Raises exception.AMIDoesNotExist if unsuccessful
        """
        try:
            return self.get_images(filters={'image-id': image_id})[0]
        except azure.WindowsAzureError as e:
            # if e.error_code == "InvalidAMIID.NotFound":
            #     raise exception.AMIDoesNotExist(image_id)
            raise
        except IndexError:
            raise exception.AMIDoesNotExist(image_id)

    def get_image_or_none(self, image_id):
        """
        Return image object representing an AMI.
        Returns None if unsuccessful
        """
        try:
            return self.get_image(image_id)
        except exception.AMIDoesNotExist:
            pass

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


class PlacementGroup(object):
    def __init__(self, service, easy_sms):
        self.name = easy_sms._unazurify(service.service_name)
        self.id = service.service_name
        self._properties = easy_sms.conn.get_hosted_service_properties(self.id, True).hosted_service_properties


class SecurityGroup(object):
    def __init__(self, pg, easy_sms):
        self.name = pg.name
        self.id = pg.id
        self.connection = easy_sms
        self.vpc_id = None
        self._properties = pg._properties
        self._service_tags = self._properties.extended_properties
        self.tags = self._load_tags()

    def instances(self):
        return self.connection.get_all_instances(filters={'instance.group-name': self.name})

    def add_tag(self, key, value):
        self.tags[key] = value
        self._update_service_tags(key, value)

    def _update_service_tags(self, key, value):
        k = key.replace('@tc-', 'tc_')
        self._service_tags[k] = value
        self.connection.conn.update_hosted_service(self.id, self._properties.label, self._properties.description,
                                                   self._service_tags)

    def _load_tags(self):
        tags = dict()
        for key,value in self._service_tags.iteritems():
            k = key.replace('tc_', '@tc-')
            tags[k] = value
        return tags


class Reservation(object):
    def __init__(self, instances):
        self.instances = instances

    def __str__(self):
        return self.instances.__str__()

class Instance(object):

    POWER_STATES = {'Starting': 'pending', 'Started': 'running' , 'Stopping': 'stopping', 'Stopped': 'stopped',
                    'Unknown': 'terminated'}

    def __init__(self, service, deployment, role_instance, role, easy_sms):
        self.role_instance = role_instance
        self.role = role
        self.service_properties = easy_sms.conn.get_hosted_service_properties(service.service_name,
                                                                      True).hosted_service_properties
        self.ports = dict()
        for endpoint in role_instance.instance_endpoints:
            self.ports[endpoint.name] = int(endpoint.public_port)

        self.id = (service.service_name, deployment.name, role.role_name)
        self.public_dns_name = deployment.url
        self.private_dns_name = deployment.url
        self.state = self.POWER_STATES[role_instance.power_state]
        self.state_code = None
        self.previous_state = None
        self.previous_state_code = None
        self.key_name = None #TODO look at CertificateStore on Azure api
        self.instance_type = role.role_size
        self.launch_time = deployment.created_time
        self.image_id = role.os_virtual_hard_disk.source_image_name
        self.placement = None
        self.placement_group = service.service_name
        self.placement_tenancy = None
        self.kernel = None
        self.ramdisk = None
        self.architecture = None
        self.hypervisor = None
        self.virtualization_type = None
        self.product_codes = None
        self.ami_launch_index = None
        self.monitored = None
        self.monitoring_state = None
        self.spot_instance_request_id = None
        self.subnet_id = None
        self.vpc_id = None
        self.private_ip_address = role_instance.ip_address
        self.ip_address = role_instance.instance_endpoints[0].vip
        self.platform = role.os_virtual_hard_disk.os.lower()
        self.root_device_name = None
        self.root_device_type = None
        self.block_device_mapping = None
        self.state_reason = role_instance.instance_state_details
        self.groups = None
        self.interfaces = None
        self.ebs_optimized = None
        self.instance_profile = None

        self.connection = easy_sms
        self.dns_name = self.ip_address #for some reason ssh not working with: deployment.url
        self.tags = dict()
        self.add_tag('alias', role.role_name)
        self.add_tag('Name', role.role_name)
        if 'key_name' in self.service_properties.extended_properties.keys():
            self.key_name = self.service_properties.extended_properties['key_name']

    def __repr__(self):
        return '<Azure Instance: %s' % (self.id,)

    def add_tag(self, k, v):
        self.tags[k]=v

    def terminate(self):
        try:
            self._terminate_role(max_tries=5, timeout=20)
        except azure.WindowsAzureError, e:
            try:
                self.connection.conn.delete_deployment(self.id[0], self.id[1])
            except WindowsAzureMissingResourceError, e:
                pass

    def _terminate_role(self, max_tries=1, timeout=30):
        try:
            self.connection.conn.delete_role(*self.id)
        except WindowsAzureConflictError, e:
            max_tries -= 1
            if max_tries < 1:
                raise
            log.info('Waiting for instance to be available...')
            time.sleep(timeout)
            self._terminate_role(max_tries, timeout)


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

        #'''
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
            image_id = 'tc-linux12-2'

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

        def test_vm_with_ssh(self):
            image_id = 'tc-linux12-2'
            pg = self.easySMS.get_or_create_placement_group('ssh_key-test')
            self.easySMS.run_instances(image_id, ['master'], pg.service_name, key_name='tethyscert')


        def test_get_all_instances(self):
            instances = self.easySMS.get_all_instances()
            print [instance.role_name for instance in instances]

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAzureUtils)
    unittest.TextTestRunner(verbosity=2).run(suite)






            # props = sms.get_hosted_service_properties(service.service_name, True)
            # if len(props.deployments) > 0 and len(props.deployments[0].role_list) > 0:
            #     if props.deployments[0].role_list[0].role_type == 'PersistentVMRole':
            #         print(props.deployments[0].role_list[0].role_name)



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