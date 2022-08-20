#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Jimisola Laursen <jimisola@jimisola.com>
# Copyright: (c) 2022, LFV <www.lfv.se>

__metaclass__ = type

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils._text import to_bytes, to_native

import os
import tempfile

LIB_IMP_ERR = None
try:
    from pykeepass import PyKeePass

    HAS_LIB = True
except Exception:
    HAS_LIB = False
    LIB_IMP_ERR = traceback.format_exc()


DOCUMENTATION = r"""
---
module: attachment
author:
  - Jimisola Laursen (@lfvjimisola)
  - Jimisola Laursen (@jimisola)

short_description: Exports KeePass attachments
description:
  - This module will export an attachment in a KeePass entry to a file.

version_added: "0.1.0"

extends_documentation_fragment:
  - files
  - action_common_attributes

requirements:
  - pykeepass

options:
  database:
    description: Path to KeePass database file
    required: true
    type: str
  password:
    description: Password for KeePass database file
    required: true
    type: str
  entrypath:
    description: Path to KeePass entry containing the attachment that should be exported
    required: true
    type: str
  attachment:
    description: Name of attachment that should be exported
    required: true
    type: str
  dest:
    description: Absolute path where the file should be exported to
    required: true
    type: str

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  platform:
    platforms: posix
"""

EXAMPLES = r"""
# Export a file
- name: Export a file from KeePass
  keepass:
    database: database.kdbx
    password: somepassword
    path: "group/subgroup/entry"
    attachment: somefile.txt
    dest: somefile_exported.txt
"""

RETURN = r""" # """


def check_file_attrs(module, result, diff):

    changed, msg = result["changed"], result["msg"]

    file_args = module.load_file_common_arguments(module.params)
    if module.set_fs_attributes_if_different(file_args, False, diff=diff):

        if changed:
            msg += " and "
        changed = True
        msg += "ownership, perms or SE linux context changed"

    result["changed"] = changed
    result["msg"] = msg

    return result


def export_attachment(module, result):
    try:
        # load database
        kp = PyKeePass(module.params["database"], password=module.params["password"])

        entrypath = module.params["entrypath"]
        dest = module.params["dest"]
        attachment = module.params["attachment"]

        # find entry
        kp_entry = kp.find_entries(path=entrypath.split("/"), first=True)

        if kp_entry is None:
            module.fail_json(msg="Entry '{0}' not found".format(entrypath))

        kp_attachment = None
        for item in kp_entry.attachments:
            if item.filename == attachment:
                kp_attachment = item

        if kp_attachment is None:
            module.fail_json(
                msg="Entry '{0}' does not contain attachment '{1}'".format(
                    entrypath, attachment
                )
            )

        b_data = kp_attachment.binary

        tmpfd, tmpfile = tempfile.mkstemp()
        f = os.fdopen(tmpfd, "wb")
        f.write(b_data)
        f.close()

        module.atomic_move(
            tmpfile,
            to_native(
                os.path.realpath(to_bytes(dest, errors="surrogate_or_strict")),
                errors="surrogate_or_strict",
            ),
            unsafe_writes=module.params["unsafe_writes"],
        )

        result["changed"] = True
        result["msg"] = "attachment '{0}' exported to file '{1}'".format(
            module.params["attachment"], dest
        )

    except Exception as e:
        result["msg"] = "Module viczem.keepass.attachment failed: {0}".format(e)
        module.fail_json(**result)

    attr_diff = None

    result = check_file_attrs(module, result, attr_diff)

    module.exit_json(**result, diff=attr_diff)


def main():
    module_args = dict(
        database=dict(type="str", required=True),
        password=dict(type="str", no_log=True, required=True),
        entrypath=dict(type="str", required=True),
        attachment=dict(type="str", required=True),
        dest=dict(type="path", required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        add_file_common_args=True,
    )

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("pykeepass"), exception=LIB_IMP_ERR)

    result = dict(
        changed=False,
    )

    dest = module.params["dest"]
    b_dest = to_bytes(dest, errors="surrogate_or_strict")

    if os.path.isdir(b_dest):
        module.fail_json(rc=256, msg="Destination {0} is a directory!".format(dest))

    export_attachment(module, result)


if __name__ == "__main__":
    main()
