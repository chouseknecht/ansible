#
# Copyright 2015 Peter Sprygada <psprygada@ansible.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.plugins.action.net_config import ActionModule as NetActionModule

class ActionModule(NetActionModule, ActionBase):

    def _map_keys(self, task_vars, args):
        args['port'] = (task_vars.get('ansible_nxapi_port') or 0)
        args['username'] = task_vars.get('ansible_nxapi_user')
        args['password'] = task_vars.get('ansible_nxapi_pass')
        args['protocol'] = task_vars.get('ansible_nxapi_proto')
