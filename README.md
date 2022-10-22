# Ansible KeePass Lookup Plugin

This collection provides plugins that allows to read data from KeePass file (modifying is not supported)

## How it works

The lookup plugin opens a UNIX socket with decrypted KeePass file. 
For performance reasons, decryption occurs only once at socket startup, 
and the KeePass file remains decrypted as long as the socket is open.
The UNIX socket file is stored in a temporary folder according to OS.

## Installation

Requirements: `python 3`, `pykeepass==4.0.3`

    pip install 'pykeepass==4.0.3' --user
    ansible-galaxy collection install viczem.keepass


## Variables

- `keepass_dbx` - path to KeePass file
- `keepass_psw` - *Optional*. Password (required if `keepass_key` is not set)
- `keepass_key` - *Optional*. Path to keyfile (required if `keepass_psw` is not set)
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

### Examples

More examples see in [/docs/examples](/docs/examples).

#### Lookup

    ansible_user             : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'username') }}"
    ansible_become_pass      : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'password') }}"
    custom_field             : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'custom_properties', 'a_custom_property_name') }}"
    attachment               : "{{ lookup('viczem.keepass.keepass', 'path/to/entry', 'attachments', 'a_file_name') }}"

#### Module
    - name: "Export file: attachment.txt"
        viczem.keepass.attachment:
          database: "{{ keepass_dbx }}"
          password: "{{ keepass_psw }}"
          entrypath: example/attachments
          attachment: "attachment.txt"
          dest: "{{ keepass_attachment_1_name }}"

## Contributing

See [/docs/contributing](docs/contributing).