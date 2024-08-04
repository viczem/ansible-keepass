# Ansible KeePass Lookup Plugin

This collection provides plugins that allows to read data from KeePass file (modifying is not supported)

## How it works

The lookup plugin opens a UNIX socket with decrypted KeePass file.
For performance reasons, decryption occurs only once at socket startup,
and the KeePass file remains decrypted as long as the socket is open.
The UNIX socket file is stored in a temporary folder according to OS.

## Installation

Requirements: `python 3`, `pykeepass>=4.0.4`

    pip install 'pykeepass>=4.0.4' --user
    ansible-galaxy collection install viczem.keepass


## Variables

- `keepass_dbx` - path to KeePass file
- `keepass_psw` - *Optional*. Password (required if `keepass_key` is not set)
- `keepass_key` - *Optional*. Path to keyfile (required if `keepass_psw` is not set)
- `keepass_ttl` - *Optional*. Socket TTL (will be closed automatically when not used).
Default 60 seconds.

## Environment Variables

If you want to use ansible-keepass with continuous integration, it could be helpful not to use ansible variables but Shell environment variables.

- `ANSIBLE_KEEPASS_PSW` Password
- `ANSIBLE_KEEPASS_KEY` Path to keyfile
- `ANSIBLE_KEEPASS_TTL` Socket TTL
- `ANSIBLE_KEEPASS_SOCKET` Path to Keepass Socket

The environment variables will only be used, if no ansible variable is set.

You can than start the socket in another background process like this
```sh
export ANSIBLE_KEEPASS_PSW=mySecret
export ANSIBLE_KEEPASS_SOCKET=/home/build/.my-ansible-sock.${CI_JOB_ID}
export ANSIBLE_TTL=600 # 10 Minutes
/home/build/ansible-pyenv/bin/python3 /home/build/.ansible/roles/ansible_collections/viczem/keepass/plugins/lookup/keepass.py /path-to/my-keepass.kdbx &
ansible-playbook -v playbook1.yml
ansible-playbook -v playbook2.yml

```

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