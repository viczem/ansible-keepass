# Ansible KeePass Lookup Plugin

This collection provides a plugin that allows to read data from KeePass file (modifying is not supported)

## How it works

The plugin opens a UNIX socket with decrypted KeePass file. 
For performance reasons, decryption occurs only once at socket startup, 
and the KeePass file remains decrypted as long as the socket is open.
The UNIX socket file is stored in a temporary folder according to OS.


## Installation

Requirements: `python 3`, `pykeepass==4.0.3`

    pip install 'pykeepass==4.0.3' --user
    ansible-galaxy collection install viczem.keepass


## Variables

- `keepass_dbx` - path to KeePass file
- `keepass_psw` - password
- `keepass_key` - *Optional*. Path to keyfile
- `keepass_ttl` - *Optional*. Socket TTL (will be closed automatically when not used). 
Default 60 seconds.


## Usage

`ansible-doc -t lookup keepass` to get description of the plugin

> **WARNING**: For security reasons, do not store KeePass passwords in plain text. 
Use `ansible-vault encrypt_string` to encrypt it and use it like below

    # file: group_vars/all

    keepass_dbx: "~/.keepass/database.kdbx"
    keepass_psw: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...encrypted password...

### Example

    ansible_user             : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'username') }}"
    ansible_become_pass      : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'password') }}"
    custom_field             : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'custom_properties', 'a_custom_property_name') }}"
    attachment               : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'attachments', 'a_file_name') }}"

More examples see in [/doc/examples](/doc/examples).
