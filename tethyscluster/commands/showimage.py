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

from completers import S3ImageCompleter


class CmdShowImage(S3ImageCompleter):
    """
    showimage <image_id>

    Show all AMI parts and manifest files on S3 for an instance-store AMI

    Example:

        $ tethyscluster showimage ami-999999
    """
    names = ['showimage', 'shimg']

    def execute(self, args):
        if not args:
            self.parser.error('please specify an AMI id')
        for arg in args:
            self.ec2.list_image_files(arg)
