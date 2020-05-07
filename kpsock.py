#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import socket
import argparse
import tempfile
import logging
from logging import config as logging_config
from getpass import getpass
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsIntegrityError


try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


def main(kdbx, psw, kdbx_key, sock_fpath, ttl=60):
    log = logging.getLogger('ansible_keepass')

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(sock_fpath)
            s.listen(1)
            s.settimeout(ttl)
            os.chmod(sock_fpath, 0o600)
            log.info('Open ansible-keepass socket. TTL={}sec'.format(ttl))

            with PyKeePass(kdbx, psw, kdbx_key) as kp:
                log.info('%s decrypted' % kdbx)
                while True:
                    log.debug('Wait a client connection')
                    conn, addr = s.accept()
                    log.debug('Client connected')
                    with conn:
                        conn.settimeout(ttl)
                        while True:
                            data = conn.recv(1024).decode()
                            if not data:
                                break

                            msg = json.loads(data)
                            if not isinstance(msg, dict):
                                raise ValueError('wrong message format')
                            if 'attr' not in msg or 'path' not in msg:
                                raise ValueError('wrong message properties')

                            path = msg['path'].strip('/')
                            attr = msg['attr']
                            log.debug("attr: %s in path: %s" % (attr, path))
                            entr = kp.find_entries_by_path(path, first=True)

                            if entr is None:
                                conn.send(
                                        _msg('error',
                                             'path %s is not found' % path))
                                log.error('path %s is not found' % path)
                                continue

                            if not hasattr(entr, attr):
                                conn.send(
                                        _msg('error',
                                             'attr %s is not found' % attr))
                                log.error('attr %s is not found' % attr)
                                continue

                            conn.send(_msg('ok', getattr(entr, attr)))
                            log.info('Fetch %s: %s', path, attr)
    except CredentialsIntegrityError:
        log.error("%s failed to decrypt" % kdbx)
        sys.exit(1)
    except FileNotFoundError as e:
        log.error(str(e))
        sys.exit(1)
    except json.JSONDecodeError as e:
        log.error("JSONDecode: %s" % e)
        sys.exit(1)
    except ValueError as e:
        log.error(str(e))
        sys.exit(1)
    except (KeyboardInterrupt, socket.timeout):
        pass
    finally:
        log.info("Close ansible-keepass socket")
        if os.path.exists(sock_fpath):
            os.remove(sock_fpath)


def _msg(status, text):
    return json.dumps({
        'status': status,
        'text': text
    }).encode()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description=(
        "Creating UNIX socket for response to requests "
        "from the keepass lookup plugin. The database and password "
        "are stay decrypted in memory while socket opened. "
        "Format of a request in JSON with the properties: attr, path. "
        "Response is JSON with properties: status, text."
    ), formatter_class=argparse.RawDescriptionHelpFormatter)

    arg_parser.add_argument(
            'kdbx', type=str, help="Path to .kdbx file")

    arg_parser.add_argument(
            '--key', type=str, nargs='?', default=None,
            help="Path to a KeePass keyfile")

    arg_parser.add_argument(
            '--ttl', type=int, nargs='?', default=60, const=60,
            help="Time-To-Live since past access in seconds. "
                 "Default is 1 minute")

    arg_parser.add_argument(
            '--log', type=str, nargs='?', default=None, const='',
            help="Path to log file. If empty string the log file will be "
                 "created in the same directory as .kdbx file with suffix .log")

    arg_parser.add_argument(
            '--log-level', type=str, nargs='?', default='INFO', choices=(
                'CRITICAL',
                'ERROR',
                'WARNING',
                'INFO',
                'DEBUG',
            ))
    args = arg_parser.parse_args()

    kdbx_fpath = os.path.realpath(os.path.expanduser(args.kdbx))
    if not os.path.exists(kdbx_fpath):
        sys.stderr.write("KeePass file %s does not exist" % kdbx_fpath)
        sys.exit(1)

    kdbx_key_fpath = None
    if args.key:
        kdbx_key_fpath = os.path.realpath(os.path.expanduser(args.key))
        if not os.path.exists(kdbx_key_fpath):
            sys.stderr.write("--key %s does not exist" % kdbx_key_fpath)
            sys.exit(1)

    # - predictable socket path for use in ansible plugin
    # - tempdir for prevent error AF_UNIX path too long
    # - only one socket can be opened
    tempdir = tempfile.gettempdir()
    if not os.access(tempdir, os.W_OK):
        sys.stderr.write("You have no write permissions to %s" % tempdir)
        sys.exit(1)

    sock_file_path = "%s/ansible-keepass.sock" % tempdir
    if os.path.exists(sock_file_path):
        sys.stderr.write("kpsock is already opened. If you sure that kpsock "
                         "closed, run: rm %s" % sock_file_path)
        sys.exit(1)

    password = getpass("Password: ")
    if isinstance(password, bytes):
        password = password.decode(sys.stdin.encoding)

    dict_config = {
        'version': 1,
        'formatters': {
            'default': {
                'format': "%(asctime)s [%(levelname)-5.5s]  %(message)s ",
                'datefmt': "%Y-%m-%d %H:%M:%S",
            }
        },
        'handlers': {
            'stdout': {
                'class': 'logging.StreamHandler',
                'formatter': 'default',
            },
        },
        'loggers': {
            'ansible_keepass': {
                'propagate': False,
                'level': args.log_level,
                'handlers': [
                    'stdout'
                ]
            }
        }
    }
    if args.log is not None:
        if args.log == '':
            log_fpath = kdbx_fpath + ".log"
        else:
            log_fpath = os.path.realpath(os.path.expanduser(args.log))
        if not os.access(os.path.dirname(log_fpath), os.W_OK | os.X_OK):
            sys.stderr.write("--log %s permission error" % log_fpath)
            sys.exit(1)
        dict_config['handlers']['file'] = {
            'class': 'logging.FileHandler',
            'filename': log_fpath,
            'formatter': 'default',
        }
        dict_config['loggers']['ansible_keepass']['handlers'].append('file')
    logging_config.dictConfig(dict_config)

    main(kdbx_fpath, password, kdbx_key_fpath, sock_file_path, args.ttl)
