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
from pykeepass import PyKeePass
from construct.core import ChecksumError
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <victor.zemtsov@gmail.com>
    version_added: '0.2'
    short_description: fetch data from KeePass file
    description:
        - This lookup returns a value of a property of a KeePass entry 
        - which fetched by given path
    options:
      _terms:
        description: 
          - first is a path to KeePass entry
          - second is a property name of the entry, e.g. username or password
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
    
    example:
      - "{{ lookup('keepass', 'path/to/entry', 'password') }}"
"""


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        if not terms or len(terms) != 2:
            raise AnsibleError('Wrong request format')
        entry_path = terms[0].strip('/')
        entry_attr = terms[1]

        kp_dbx = variables.get('keepass_dbx', '')
        kp_dbx = os.path.realpath(os.path.expanduser(kp_dbx))
        if os.path.isfile(kp_dbx):
            display.v(u"Keepass: database file %s" % kp_dbx)
        kp_soc = "%s.sock" % kp_dbx
        if os.path.exists(kp_soc):
            return self._fetch_socket(kp_soc, entry_path, entry_attr)
        kp_psw = variables.get('keepass_psw', '')
        kp_key = variables.get('keepass_key')
        return self._fetch_file(
                kp_dbx, str(kp_psw), kp_key, entry_path, entry_attr)

    def _fetch_file(self, kp_dbx, kp_psw, kp_key, entry_path, entry_attr):
        if kp_key:
            kp_key = os.path.realpath(os.path.expanduser(kp_key))
            if os.path.isfile(kp_key):
                display.vvv(u"Keepass: database keyfile: %s" % kp_key)

        try:
            with PyKeePass(kp_dbx, kp_psw, kp_key) as kp:
                entry = kp.find_entries_by_path(entry_path, first=True)
                if entry is None:
                    raise AnsibleError(u"Entry '%s' is not found" % entry_path)
                display.vv(
                    u"KeePass: attr: %s in path: %s" % (entry_attr, entry_path))
                return [getattr(entry, entry_attr)]
        except ChecksumError:
            raise AnsibleError("Wrong password/keyfile {}".format(kp_dbx))
        except (AttributeError, FileNotFoundError) as e:
            raise AnsibleError(e)

    def _fetch_socket(self, kp_soc, entry_path, entry_attr):
        display.vvvv(u"KeePass: try to socket connect")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(kp_soc)
        display.vvvv(u"KeePass: connected")
        sock.send(json.dumps({'attr': entry_attr, 'path': entry_path}).encode())
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
