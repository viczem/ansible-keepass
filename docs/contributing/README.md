# Contributing

1. Create ansible.cfg in cloned directory:

```
[defaults]
COLLECTIONS_PATH = ./collections
```

2. Create requirements.yml in cloned directory:

```
---
collections:
  - name: namespace.collection_name
    source: /where/is/your/clone
    type: dir
```


3. To install the collection _locally_ in your cloned directory, just install it through ansible-galaxy
```shell
rm -rf ./collections && ansible-galaxy install -r requirements.yml
```

Note: Any change on your clone imply to reinstall the collection.


Tip: You can place a ansible.cfg with `COLLECTIONS_PATH = ../../collections` in the examples dictory if you want to run the example on local collection in your cloned directory.
