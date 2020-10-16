# Ansible KeePass Lookup Plugin

Perhaps, from a security view point, this solution is the same as `ansible-vault`.
Just if you are storing secrets data in KeePass, then why not use it, 
instead of duplicating to `ansible-vault`. 


## Installation

Dependency: `pykeepass`

    pip install pykeepass --user
    mkdir -p ~/.ansible/plugins/lookup && cd "$_"
    curl https://raw.githubusercontent.com/dszryan/ansible-keepass/master/keepass.py -o ./keepass.py

[More about ansible plugins installation](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html)


## Variables

- `keepass` - definition of keepass databases in the structure shown below

  keepass:
    - name: primary
      location: ~/keepass.kdbx
      password: !vault ...
      keyfile: !vault ...

## Usage

For global variables define them once in `group_vars/all`.

For security reasons, do not store KeePass password in plain text. 
Use `ansible-vault encrypt_string` to encrypt the password. 
I'm not sure, but I think that for simplicity, 
it is safe to use the same `ansible-vault` password as KeePass password.
To decrypt the passwod use `--ask-vault-pass`
 e.g. `ansible all -m ping --ask-vault-pass`.


    # file: group_vars/all
    
    keepass_dbx: "~/.keepass/database.kdbx"
    keepass_psw: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...

## Example

Define variables you need e.g. in any file in group_vars

    keepass:
      - name: primary
        location: ~/keepass.kdbx
        password: !vault ...
        keyfile: !vault ...
    ansible_user                : "{{ lookup('keepass', 'primary', 'path/to/entry', 'username') }}"
    ansible_become_pass         : "{{ lookup('keepass', 'primary', 'path/to/entry', 'password') }}"
    ansible_custom_field        : "{{ lookup('keepass', 'primary', 'path/to/entry', 'custom_field_property') }}"
    ansible_ssh_private_key_file: "{{ lookup('keepass', 'primary', 'path/to/entry', 'ssh_rsa_identity.file') | b64decode }}"


You can get another [properties of an KeePass entry](https://github.com/pschmitt/pykeepass/blob/master/pykeepass/entry.py)
(not only `username` or `password`)

Specify a boolean value of true to use custom field properties
 
`ansible-doc -t lookup keepass` - to get description of the plugin
