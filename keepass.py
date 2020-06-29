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
from pykeepass import PyKeePass
from construct.core import ChecksumError
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
#import pprint ### DEBUG

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
          - if second parameter is "*" then the whole subtree under <first_param>
            is returned with the leaf entries containing { username.. password }
            (currently this works only for _fetch_file!!)
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
      - https://github.com/duhlig/ansible-keepass

    examples:
      - "{{ lookup('keepass', 'path/to/entry', 'password') }}"
      - dbpasswords: "{{ lookup('keepass', inventory_hostname, '*') }}"
"""


class LookupModule(LookupBase):
    keepass = None
    num_groups = 0
    num_entries = 0
    #pp = pprint.PrettyPrinter(indent=4) ### DEBUG

    def run(self, terms, variables=None, **kwargs):
        if not terms or len(terms) < 2 or len(terms) > 3:
            raise AnsibleError('Wrong request format')
        entry_path = terms[0].strip('/')
        entry_attr = terms[1]
        enable_custom_attr = False
        
        if len(terms) == 3:
            enable_custom_attr = terms[2]
        
        kp_dbx = variables.get('keepass_dbx', '')
        display.vvv(u"Keepass: want database file %s" % kp_dbx)
        kp_dbx = os.path.realpath(os.path.expanduser(kp_dbx))
        if os.path.isfile(kp_dbx):
            display.v(u"Keepass: database file %s" % kp_dbx)

        kp_soc = "%s/ansible-keepass.sock" % tempfile.gettempdir()
        if os.path.exists(kp_soc):
            display.v(u"Keepass: fetch from socket")
            return self._fetch_socket(kp_soc, entry_path, entry_attr)

        kp_psw = variables.get('keepass_psw', '')
        kp_key = variables.get('keepass_key')
        display.v(u"Keepass: fetch from kdbx file")
        return self._fetch_file(
                kp_dbx, str(kp_psw), kp_key, entry_path, entry_attr, enable_custom_attr)

    def _fetch_file(self, kp_dbx, kp_psw, kp_key, entry_path, entry_attr, enable_custom_attr):
        try:
            FileNotFoundError
        except NameError:
            FileNotFoundError = IOError

        if kp_key:
            kp_key = os.path.realpath(os.path.expanduser(kp_key))
            if os.path.isfile(kp_key):
                display.vvv(u"Keepass: database keyfile: %s" % kp_key)

        try:
            if not LookupModule.keepass:
                LookupModule.keepass = PyKeePass(kp_dbx, kp_psw, kp_key)
            if entry_attr == "*":
                entry = [ self._getpwtree(LookupModule.keepass.tree.getroot(), entry_path) ]
                if entry is None:
                    raise AnsibleError(u"Entry '%s' is not found" % entry_path)
                display.vv(
                    u"KeePass: path: %s contains %d groups and %d entries" %
                    (entry_path, self.num_groups, self.num_entries))
                return entry
            else:
                entry = LookupModule.keepass.\
                    find_entries_by_path(entry_path, first=True)
                if entry is None:
                    raise AnsibleError(u"Entry '%s' is not found" % entry_path)
                display.vv(
                    u"KeePass: attr: %s in path: %s" % (entry_attr, entry_path))
                entry_val = None
                if enable_custom_attr:
                    entry_val = entry.get_custom_property(entry_attr)
                    if entry_val is not None:
                        return [entry_val]
                    else:
                        raise AnsibleError(AttributeError(u"'No custom field property '%s'" % (entry_attr)))
                else:
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

    def _getpwtree(self, root, entry_path):
        if root == None:
            return None
        for elem in root:
            if elem.tag == 'Root':
                return self._pwtree(elem, entry_path, entry_path == "", True)
        return None

    def _pwtree(self, elem, entry_path, found, firstgroup):
        if elem == None:
            return {}
        elif elem.tag == 'Entry' and found:
            return self._getunpw(elem)
        elif elem.tag == 'Group':
            return self._getgrp(elem, entry_path, found, firstgroup)
        else:
            _pw = {}
            for subelem in elem:
                _pw = self._merge_dicts(_pw, self._pwtree(subelem, entry_path, found, firstgroup))
            return _pw

    def _getgrp(self, grp, entry_path, found, firstgroup):
        _pw = {}
        _gname = ""
        foundnow = False
        gpath = entry_path.split('/', 1)
        if len(gpath) == 1:
            gpath.append("")
        # first find the group name
        for attr in grp:
            if attr.tag == 'Name':
                if attr.text == 'Recycle Bin':
                    return {}
                else:
                    _gname = attr.text
        if _gname == "":
            return {}
        if not found and gpath[0] == _gname:
            found = (gpath[1] == "")
            foundnow = True
        if firstgroup or found or foundnow:
            if not firstgroup:
                entry_path = gpath[1]
            for attr in grp:
                _pw = self._merge_dicts(_pw, self._pwtree(attr, entry_path, found, False))
        if firstgroup or not found or foundnow:
            return _pw
        else:
            self.num_groups += 1
            return {_gname: _pw}

    def _getunpw(self, entry):
        idx = -1
        val = ""
        unpw = ["", ""]
        for a in entry:
            if a.tag == 'String':
                for kv in a:
                    if kv.tag == 'Key':
                        if kv.text == 'UserName':
                            idx = 0
                        elif kv.text == 'Password':
                            idx = 1
                    elif kv.tag == 'Value':
                        val = kv.text
                if idx != -1:
                    unpw[idx] = val
                    idx = -1
        if unpw[0] != "":
            self.num_entries += 1
            return {unpw[0]: unpw[1]}
        else:
            return {}

    # taken from https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression-in-python
    def _merge_dicts(self, x, y):
        """Given two dictionaries, merge them into a new dict as a shallow copy."""
        z = x.copy()
        z.update(y)
        return z
