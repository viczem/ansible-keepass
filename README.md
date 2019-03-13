# Ansible KeePass Lookup Plugin

Perhaps, from a security view point, this solution is the same as `ansible-vault`.
Just if you are storing secrets data in KeePass, then why not use it, 
instead of duplicating to `ansible-vault`. 


## Installation

    pip install pykeepass --user
    mkdir -p ~/.ansible/plugins/lookup && cd "$_"
    curl https://raw.githubusercontent.com/viczem/ansible-keepass/master/keepass.py -o ./keepass.py

[More about ansible plugins installation](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html)


## Variables

- `keepass_dbx` - path to Keepass database file
- `keepass_psw` - password
- `keepass_key` - *optional* path to keyfile


## Usage

For global variables define them once in `group_vars/all`.

For security reasons, do not store KeePass database password in plain text. 
Use `ansible-vault encrypt_string` to encrypt the password. 
I'm not sure, but I think that for simplicity, 
it is safe to use the same `ansible-vault` password as KeePass database password.
To decrypt the passwod use `--ask-vault-pass`
 e.g. `ansible all -m ping --ask-vault-pass`.


    # file: group_vars/all
    
    keepass_dbx: "~/.keepass/database.kdbx"
    keepass_psw: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...

  
Now you can create another variables you need e.g. in any file in group_vars


    ansible_user       : "{{ lookup('keepass', 'path/to/entry', 'username') }}"
    ansible_become_pass: "{{ lookup('keepass', 'path/to/entry', 'password') }}"


You can get another [properties of an KeePass entry](https://github.com/pschmitt/pykeepass/blob/master/pykeepass/entry.py)
(not only `username` or `password`)

 
`ansible-doc -t lookup keepass` - to get description of the plugin