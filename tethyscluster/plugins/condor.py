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

from tethyscluster import clustersetup
from tethyscluster.templates import condor
from tethyscluster.logger import log
from tethyscluster.node import WindowsNode, UbuntuNode, Node

CONDOR_CFG = '/etc/condor/config.d/40tethyscluster'
FS_REMOTE_DIR = '/home/._condor_tmp'


class CondorPlugin(clustersetup.DefaultClusterSetup):

    def start_condor_cmd(self, node):
        if isinstance(node, WindowsNode):
            return 'cygrunsrv -S condor; condor_restart'
        elif isinstance(node, UbuntuNode):
            return '/etc/init.d/condor start'
        else:
            return 'condor_master'

    def condor_tmpl(self, node):
        if isinstance(node, WindowsNode):
            return condor.condor_windows_tmpl
        else:
            return condor.condor_linux_tmpl


    def _add_condor_node(self, node):
        condor_cfg_dir = node.ssh.execute('condor_config_val local_config_dir')[0]
        node.ssh.mkdir(condor_cfg_dir, ignore_failure=True)
        CONDOR_CFG = condor_cfg_dir + '/tethyscluster'
        condorcfg = node.ssh.remote_file(CONDOR_CFG, 'w')
        daemon_list = "MASTER, STARTD, SCHEDD"
        if node.is_master():
            daemon_list += ", COLLECTOR, NEGOTIATOR"
        ctx = dict(CONDOR_HOST='master', DAEMON_LIST=daemon_list,
                   FS_REMOTE_DIR=FS_REMOTE_DIR)
        condorcfg.write(self.condor_tmpl(node) % ctx)
        condorcfg.close()
        node.ssh.execute('pkill condor', ignore_exit_status=True)
        config_vars = ["LOCAL_DIR", "LOG", "SPOOL", "RUN", "EXECUTE", "LOCK",
                       "CRED_STORE_DIR"]
        config_vals = ['$(condor_config_val %s)' % var for var in config_vars]
        node.ssh.execute('mkdir -p %s' % ' '.join(config_vals))
        node.ssh.execute('chown -R condor:condor %s' % ' '.join(config_vals))
        node.ssh.execute(self.start_condor_cmd(node))

    def _setup_condor(self, master=None, nodes=None):
        log.info("Setting up Condor grid")
        master = master or self._master
        if not master.ssh.isdir(FS_REMOTE_DIR):
            # TODO: below should work but doesn't for some reason...
            # master.ssh.mkdir(FS_REMOTE_DIR, mode=01777)
            master.ssh.mkdir(FS_REMOTE_DIR)
            master.ssh.chmod(01777, FS_REMOTE_DIR)
        nodes = nodes or self.nodes
        log.info("Starting Condor master")
        self._add_condor_node(master)
        log.info("Starting Condor nodes")
        for node in nodes:
            self.pool.simple_job(self._add_condor_node, (node,),
                                 jobid=node.alias)
        self.pool.wait(numtasks=len(nodes))

    def run(self, nodes, master, user, user_shell, volumes):
        self._nodes = nodes
        self._master = master
        self._user = user
        self._user_shell = user_shell
        self._volumes = volumes
        self._setup_condor()

    def on_add_node(self, node, nodes, master, user, user_shell, volumes):
        self._nodes = nodes
        self._master = master
        self._user = user
        self._user_shell = user_shell
        self._volumes = volumes
        log.info("Adding %s to Condor" % node.alias)
        self._add_condor_node(node)

    def on_remove_node(self, node, nodes, master, user, user_shell, volumes):
        self._nodes = nodes
        self._master = master
        self._user = user
        self._user_shell = user_shell
        self._volumes = volumes
        log.info("Removing %s from Condor peacefully..." % node.alias)
        master.ssh.execute("condor_off -peaceful %s" % node.alias)
        node.ssh.execute("pkill condor", ignore_exit_status=True)
