#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import socket
import argparse
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass
from pykeepass import PyKeePass
from construct.core import ChecksumError


def make(kdbx, psw, kdbx_key):
    kdbx = os.path.realpath(os.path.expanduser(kdbx))
    kdbx_key = os.path.realpath(
            os.path.expanduser(kdbx_key)) if kdbx_key else None
    salt_file = '%s.salt' % kdbx
    try:
        with PyKeePass(kdbx, psw, kdbx_key) as _:
            pass

        with open(salt_file, 'wb') as f:
            f.write(Fernet.generate_key())

        os.chmod(salt_file, 0o600)
        with open(salt_file, 'rb') as f:
            psw = Fernet(f.read()).encrypt(psw.encode())

        return psw.decode()
    except (ChecksumError, InvalidToken):
        print("Wrong password or keyfile")
        sys.exit(1)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)


def run(kdbx, psw, kdbx_key, ttl=300):
    psw = psw.encode()
    kdbx = os.path.realpath(os.path.expanduser(kdbx))
    kdbx_key = os.path.realpath(
        os.path.expanduser(kdbx_key)) if kdbx_key else None

    salt_file = '%s.salt' % kdbx
    sock_file = '%s.sock' % kdbx

    if os.path.exists(sock_file):
        os.remove(sock_file)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(sock_file)
            s.listen(1)
            s.settimeout(ttl)
            os.chmod(sock_file, 0o600)
            print("## Open KeePass socket")

            while True:
                print("## Client disconnected / await a client connection")
                conn, addr = s.accept()
                print("## Client connected")
                with conn:
                    conn.settimeout(ttl)
                    while True:
                        data = conn.recv(1024).decode()
                        # a socket client disconnection
                        if not data:
                            break

                        msg = json.loads(data)
                        if not isinstance(msg, dict):
                            raise ValueError('wrong message format')
                        if 'attr' not in msg or 'path' not in msg:
                            raise ValueError('wrong message properties')

                        with open(salt_file, 'rb') as f:
                            with PyKeePass(
                                    kdbx,
                                    Fernet(f.read()).decrypt(psw).decode(),
                                    kdbx_key
                            ) as kp:
                                path = msg['path'].strip('/')
                                attr = msg['attr']
                                print(">> attr: %s in path: %s" % (attr, path))
                                entr = kp.find_entries_by_path(path, first=True)

                                if entr is None:
                                    conn.send(_msg(
                                            'error',
                                            'path %s is not found' % path))
                                    continue

                                if not hasattr(entr, attr):
                                    conn.send(_msg(
                                            'error',
                                            'attr %s is not found' % attr))
                                    continue
                                conn.send(_msg('ok', getattr(entr, attr)))

    except (ChecksumError, InvalidToken):
        print("Wrong password or keyfile")
        sys.exit(1)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("JSONDecode: %s" % e)
        sys.exit(1)
    except ValueError as e:
        print(e)
        sys.exit(1)
    except (KeyboardInterrupt, socket.timeout):
        pass
    finally:
        print("## Close KeePass socket")
        os.remove(salt_file)
        os.remove(sock_file)


def _msg(status, text):
    print("<< status: '%s'" % status)
    return json.dumps({
        'status': status,
        'text': text
    }).encode()


if __name__ == "__main__":
    _prs = argparse.ArgumentParser(description=(
        "Creates UNIX socket in the same directory as KeePass database file. "
        "Need for receive requests from the keepass lookup plugin "
        "and for response to it. "
        "The password will be crypted and key for decrypt it will be sotered "
        "in a temporary file in the same directory as the socket.\n "
        "The database and password are not stay decrypted in memory. "
        "After the lookup plugin sent a request to receive a data the password "
        "and Keepass database will be in decrypted state at the moment only.\n "
        "Format of a request in JSON with the properties: attr, path. "
        "Response is JSON with properties: status, text."
    ), formatter_class=argparse.RawDescriptionHelpFormatter)

    _prs.add_argument('kdbx', help="path to .kdbx file")
    _prs.add_argument('--key', nargs='?', default=None,
                      help="path to a KeePass keyfile")
    _prs.add_argument('--ttl', nargs='?', default=300, const=300,
                      help="Time-To-Live since past access in seconds. "
                           "Default is 5 minutes")
    _arg = _prs.parse_args()
    _psw = getpass("Password: ")
    _psw = make(_arg.kdbx, _psw, _arg.key)
    run(_arg.kdbx, _psw, _arg.key, int(_arg.ttl))
