# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    lookup: keepass
    author: dszryan
    version_added: '0.3'
    short_description: fetch data from KeePass file
    description:
        - This lookup returns a value of a property of a KeePass entry 
        - which fetched by given path
    options:
      _terms:
        description: 
          - name of the database from the list
          - second is a path to KeePass entry
          - third is a property name of the entry, e.g. property/custom property/attachment
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
    
    sample definition:
      keepass:
        - name: primary
          location: ~/keepass.kdbx
          password: !vault ...
          keyfile: !vault ...

    sample lookup:
      - "{{ lookup('keepass', 'primary', 'path/to/entry', 'property') }}"
"""
import os
import base64
import uuid
from pykeepass import PyKeePass
from construct.core import ChecksumError
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()


class LookupModule(LookupBase):
    keepass = {}

    def run(self, terms, variables=None, **kwargs):
        if not terms or not (3 <= len(terms) <= 4):
            raise AnsibleError('Wrong request format')
        database_name = terms[0]
        entry_path = terms[1].strip('/')
        entry_attribute = terms[2]
        default_value = terms[3] if len(terms) == 4 else None
        database_list = variables.get('keepass', '')

        # find database in list
        database_details = [db for db in database_list if db["name"] == database_name][0]
        if database_details is None:
            raise AnsibleError(u"Database definition for '%s' not found" % database_name)

        # get database location
        database_location = os.path.realpath(os.path.expanduser(database_details.get("location")))
        if os.path.isfile(database_location):
            display.v(u"Keepass: database file %s" % database_location)

        # get database password
        database_password = database_details.get("password", '')

        # get database keyfile
        database_keyfile = database_details.get("keyfile", None)
        if database_keyfile:
            database_keyfile = os.path.realpath(os.path.expanduser(database_keyfile))
            if os.path.isfile(database_keyfile):
                display.vvv(u"Keepass: database keyfile: %s" % database_keyfile)

        try:
            # open database
            if LookupModule.keepass.get(database_name, None) is None:
                LookupModule.keepass[database_name] = PyKeePass(database_location, database_password, database_keyfile)

            # find entry
            entry = LookupModule.keepass[database_name].find_entries_by_path(entry_path, first=True)
            if entry is None:
                raise AnsibleError(u"Entry '%s' is not found" % entry_path)
            display.vv(u"KeePass: %s[%s]" % (entry_path, entry_attribute))

            # get entry value
            entry_val = getattr(entry, entry_attribute, None) or \
                        entry.custom_properties.get(entry_attribute, None) or \
                        ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == entry_attribute][0] or None) or \
                        default_value

            if entry_attribute in ['title', 'username', 'password', 'url', 'notes', 'uuid'] :
                if hasattr(entry_val, 'startswith') and entry_val.startswith('{REF:') :
                    reference_value = uuid.UUID(entry_val.split(":")[2].strip('}'))
                    entry = LookupModule.keepass[database_name].find_entries_by_uuid(reference_value, first=True)
                    entry_val = getattr(entry, entry_attribute, default_value)

            if len(terms) == 4 or entry_val != None :
                return [base64.b64encode(entry_val.binary) if hasattr(entry_val, 'binary') else entry_val]

            raise AnsibleError(AttributeError(u"'No property/file found '%s'" % entry_attribute))

        except ChecksumError:
            raise AnsibleError("Wrong password/keyfile {}".format(database_location))
        except (AttributeError, FileNotFoundError) as e:
            raise AnsibleError(e)
