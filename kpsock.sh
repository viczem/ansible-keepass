#!/bin/sh

read_password()
{
    stty -echo
    trap 'stty echo' EXIT
    read -r "$@"
    stty echo
    trap - EXIT
    echo
}

KDBX="$1"       # Path to KeePass database file
KDBX_KEY="$2"   # Path to key file [optional]

if [ -z "$KDBX" ] || [ ! -r "$KDBX" ]; then
  echo "KeePass database file is not found"
  exit 1
fi

if [ -n "$KDBX_KEY" ] && [ ! -r "$KDBX_KEY" ]; then
    echo "KeePass key file is not found"
    exit 1
fi

printf 'Password: '; read_password PSW
PSW=$(python -c "from kpsock import make; print(make('$KDBX', '$PSW', '$KDBX_KEY'))")

if [ "$?" -ne "0" ]; then
    echo $PSW
    exit 1
fi
python -c "from kpsock import run; run('$KDBX', '$PSW', '$KDBX_KEY')" > /dev/null 2>&1 &
unset PSW
