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

from completers import InstanceCompleter


class CmdShowConsole(InstanceCompleter):
    """
    showconsole <instance-id>

    Show console output for an EC2 instance

    Example:

        $ tethyscluster showconsole i-999999

    This will display the startup logs for instance i-999999
    """
    names = ['showconsole', 'sc']

    def execute(self, args):
        if not len(args) == 1:
            self.parser.error('please provide an instance id')
        instance_id = args[0]
        self.ec2.show_console_output(instance_id)
