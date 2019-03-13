# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

import os
from pykeepass import PyKeePass
from construct.core import ChecksumError
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <victor.zemtsov@gmail.com>
    version_added: '0.1'
    short_description: fetch data from KeePass file
    description:
        - This lookup returns a value of a property of a KeePass entry which fetched by given path.
        - Required variables are
        - keepass_dbx - path to database file and 
        - keepass_psw - password. 
        - Optional variable is keepass_key - path to key file
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

        keepass_psw = variables.get('keepass_psw', '')
        keepass_dbx = variables.get('keepass_dbx', '')
        keepass_dbx = os.path.realpath(os.path.expanduser(keepass_dbx))
        if os.path.isfile(keepass_dbx):
            display.v(u"Found Keepass database file: %s" % keepass_dbx)

        keepass_key = variables.get('keepass_key')
        if keepass_key:
            keepass_key = os.path.realpath(os.path.expanduser(keepass_key))
            if os.path.isfile(keepass_key):
                display.v(u"Found Keepass database keyfile: %s" % keepass_dbx)

        try:
            with PyKeePass(keepass_dbx, keepass_psw, keepass_key) as kp:
                entry = kp.find_entries_by_path(entry_path, first=True)
                if entry is None:
                    raise AnsibleError(u"Entry '%s' is not found" % entry_path)
                return [getattr(entry, entry_attr)]
        except ChecksumError:
            raise AnsibleError("Wrong password/keyfile {}".format(keepass_dbx))
        except (AttributeError, FileNotFoundError) as e:
            raise AnsibleError(e)
