# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

import os
import json
import socket
import tempfile
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <victor.zemtsov@gmail.com>
    version_added: '0.4.0'
    short_description: fetch data from KeePass file
    description:
        - This lookup returns a value of a property of a KeePass entry 
        - which fetched by given path
    options:
      _terms:
        description: 
          - first is a path to KeePass entry
          - second is a property name of the entry, e.g. username or password
          - third (optional property) if true custem_field_property is return
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
    
    example:
      - "{{ lookup('keepass', 'path/to/entry', 'password') }}"
"""


class LookupModule(LookupBase):
    keepass = None

    def run(self, terms, variables=None, **kwargs):
        if not terms or len(terms) < 2 or len(terms) > 3:
            raise AnsibleError('Wrong request format')

        if variables is not None:
            self._templar.available_variables = variables
        variables_for_templating = getattr(self._templar, '_available_variables', {})

        entry_path = terms[0].strip('/')
        entry_attr = terms[1]
        enable_custom_attr = False
        
        if len(terms) == 3:
            enable_custom_attr = terms[2]
        
        kp_dbx = self._templar.template(variables_for_templating.get('keepass_dbx', ''), fail_on_undefined=True)
        kp_dbx = os.path.realpath(os.path.expanduser(kp_dbx))
        if os.path.isfile(kp_dbx):
            display.v(u"Keepass: database file %s" % kp_dbx)

        kp_soc = "%s/ansible-keepass.sock" % tempfile.gettempdir()
        if os.path.exists(kp_soc):
            display.v(u"Keepass: fetch from socket")
            return self._fetch_socket(kp_soc, entry_path, entry_attr, enable_custom_attr)

    def _fetch_socket(self, kp_soc, entry_path, entry_attr, enable_custom_attr):
        display.vvvv(u"KeePass: try to socket connect")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(kp_soc)
        display.vvvv(u"KeePass: connected")
        data = {'attr': entry_attr, 'path': entry_path}
        if enable_custom_attr:
          data['enable_custom_attr'] = True
        sock.send(json.dumps(data).encode())
        display.vv(u"KeePass: attr: %s in path: %s" % (entry_attr, entry_path))
        try:
            msg = json.loads(sock.recv(1024).decode())
        except json.JSONDecodeError as e:
            raise AnsibleError(str(e))
        finally:
            sock.close()
            display.vvvv(u"KeePass: disconnected")

        if msg['status'] == 'error':
            raise AnsibleError(msg['text'])
        return [msg['text']]
