# Example


## ansible

`ansible-playbook example-playbook.yml --ask-vault-pass`

or

`python kpsock.py example.kdbx`

`ansible-playbook example-playbook.yml`

## example.kdbx
### password
`spamham`
### tree
```
/
    [title: spam, username: root, password: ...]    
    
    /example
        [title: ham, username: user, password: ...]
```