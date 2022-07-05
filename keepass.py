__metaclass__ = type

import os
import re
import socket
import tempfile
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

import time
import subprocess
import sys
import argparse
import getpass
import hashlib
import traceback
import stat


DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <viczem.dev@gmail.com>
    version_added: '0.4.1'
    short_description: Fetching data from KeePass file
    description:
        - This lookup returns a value of a property of a KeePass entry 
        - which fetched by given path
    options:
      _terms:
        description: 
          - first is a path to KeePass entry
          - second is a property name of the entry, e.g. username or password
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
    
    examples:
      - "{{ lookup('keepass', 'path/to/entry', 'username') }}"
      - "{{ lookup('keepass', 'path/to/entry', 'password') }}"
      - "{{ lookup('keepass', 'path/to/entry', 'custom_properties', 'a_custom_property_name') }}"
"""


display = Display()


class LookupModule(LookupBase):
    keepass = None

    def _var(self, var_value):
        return self._templar.template(var_value, fail_on_undefined=True)

    def run(self, terms, variables=None, **kwargs):
        if not terms:
            raise AnsibleError("KeePass: arguments is not set")
        if not all(isinstance(_, str) for _ in terms):
            raise AnsibleError("KeePass: invalid argument type, all must be string")

        if variables is not None:
            self._templar.available_variables = variables
        variables_ = getattr(self._templar, "_available_variables", {})

        # Check keepass database file (required)
        var_dbx = self._var(variables_.get("keepass_dbx", ""))
        if not var_dbx:
            raise AnsibleError("KeePass: 'keepass_dbx' is not set")
        var_dbx = os.path.realpath(os.path.expanduser(os.path.expandvars(var_dbx)))
        if not os.path.isfile(var_dbx):
            raise AnsibleError("KeePass: '%s' is not found" % var_dbx)

        # Check key file (optional)
        var_key = self._var(variables_.get("keepass_key", ""))
        if var_key:
            var_key = os.path.realpath(os.path.expanduser(os.path.expandvars(var_key)))
            if not os.path.isfile(var_key):
                raise AnsibleError("KeePass: '%s' is not found" % var_key)

        # Check password (required)
        var_psw = self._var(variables_.get("keepass_psw", ""))
        if not var_psw:
            raise AnsibleError("KeePass: 'keepass_psw' is not set")

        # TTL of keepass socket (optional, default: 60 seconds)
        var_ttl = self._var(str(variables_.get("keepass_ttl", "60")))

        socket_path = _keepass_socket_path(var_dbx)

        try:
            # If UNIX socket file is not exists then the socket is not running
            stat.S_ISSOCK(os.stat(socket_path).st_mode)
        except FileNotFoundError:
            lock_file_ = socket_path + ".lock"
            if not os.path.isfile(lock_file_):
                open(lock_file_, 'a').close()

                cmd = [
                    "/usr/bin/env",
                    "python3",
                    os.path.abspath(__file__),
                    var_dbx,
                    socket_path,
                    var_ttl,
                ]
                if var_key:
                    cmd.append("--key=%s" % var_key)
                try:
                    display.v("KeePass: run socket for %s" % var_dbx)
                    subprocess.Popen(cmd)
                except OSError:
                    os.remove(lock_file_)
                    raise AnsibleError(traceback.format_exc())

            attempts = 10
            success = False
            for _ in range(attempts):
                try:
                    display.vvv("KeePass: try connect to socket %s/%s" % (_, attempts))
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(socket_path)
                    # send password to the socket for decrypt keepass dbx
                    display.vvv("KeePass: send password to '%s'" % socket_path)
                    sock.send(_rq("password", str(var_psw)))
                    resp = sock.recv(1024).decode().splitlines()

                    if len(resp) == 2 and resp[0] == "password":
                        if resp[1] == "0":
                            success = True
                        else:
                            sock.send(_rq("close"))
                            raise AnsibleError("KeePass: wrong dbx password")
                    sock.close()
                    break
                except FileNotFoundError:
                    # wait until the above command open the socket
                    time.sleep(1)

            if not success:
                raise AnsibleError("KeePass: socket connection failed for %s" % var_dbx)
            display.v("KeePass: open socket for %s -> %s" % (var_dbx, socket_path))

        if len(terms) == 1 and terms[0] in ("quit", "exit", "close"):
            self._send(socket_path, terms[0], [])
        else:
            # Fetching data from the keepass socket
            return self._send(socket_path, "fetch", terms)

    def _send(self, kp_soc, cmd, terms):
        display.vvv("KeePass: connect to '%s'" % kp_soc)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            sock.connect(kp_soc)
        except FileNotFoundError:
            raise AnsibleError("KeePass: '%s' is not found" % kp_soc)

        try:
            display.vvv("KeePass: %s %s" % (cmd, terms))
            sock.send(_rq(cmd, *terms))

            resp = sock.recv(1024).decode().splitlines()
            resp_len = len(resp)
            if resp_len == 0:
                raise AnsibleError("KeePass: '%s' result is empty" % cmd)

            if resp_len == 3:
                if resp[0] != cmd:
                    raise AnsibleError(
                        "KeePass: received command '%s', expected '%s'" % (resp[0], cmd)
                    )
                if resp[1] == "0":
                    return [resp[2]]
                else:
                    raise AnsibleError("KeePass: '%s' has error '%s'" % (resp[2], cmd))

        except Exception as e:
            raise AnsibleError(str(e))
        finally:
            sock.close()
            display.vvv("KeePass: disconnect from '%s'" % kp_soc)


def _keepass_socket(kdbx, kdbx_key, sock_path, ttl=60, kdbx_password=None):
    """

    :param str kdbx:
    :param str kdbx_key:
    :param str sock_path:
    :param int ttl: in seconds
    :return:

    Socket messages have multiline format.
    First line is a command for both messages are request and response
    """
    try:
        os.umask(0o177)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(sock_path)
            s.listen(1)
            if ttl > 0:
                s.settimeout(ttl)
            if kdbx_password:
                kp = PyKeePass(kdbx, kdbx_password, kdbx_key)
            else:
                kp = None

            is_open = True

            while is_open:
                conn, addr = s.accept()
                with conn:
                    if ttl > 0:
                        conn.settimeout(ttl)
                    while True:
                        data = conn.recv(1024).decode()
                        if not data:
                            break

                        rq = data.splitlines()
                        if len(rq) == 0:
                            conn.send(_resp("", 1, "empty request"))
                            break

                        cmd, *arg = rq
                        arg_len = len(arg)

                        # CMD: quit | exit | close
                        if arg_len == 0 and cmd in ("quit", "exit", "close"):
                            conn.send(_resp(cmd, 0))
                            conn.close()
                            is_open = False
                            break

                        # CMD: password
                        if kp is None:
                            if arg_len == 0:
                                conn.send(_resp("password", 1))
                                break
                            if cmd == "password" and arg[0]:
                                kp = PyKeePass(kdbx, arg[0], kdbx_key)
                                conn.send(_resp("password", 0))
                                break
                            else:
                                conn.send(_resp("password", 1))
                                break

                        # CMD: fetch
                        # Read data from decrypted KeePass file
                        if cmd != "fetch":
                            conn.send(_resp("fetch", 1, "unknown command '%s'" % cmd))
                            break

                        if arg_len == 0:
                            conn.send(_resp("fetch", 1, "path is not set"))
                            break

                        if arg_len == 1:
                            conn.send(
                                _resp(
                                    "fetch",
                                    1,
                                    "property name is not set for '%s'" % arg[0],
                                )
                            )
                            break

                        path = [
                            _.replace("\\/", "/")
                            for _ in re.split(r"(?<!\\)/", arg[0])
                            if _ != ""
                        ]
                        entry = kp.find_entries_by_path(path, first=True)

                        if entry is None:
                            conn.send(
                                _resp("fetch", 1, "path '%s' is not found".format(path))
                            )
                            break

                        prop = arg[1]
                        if prop == "custom_properties":
                            if arg_len == 2:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "custom_property key is not set "
                                        "for '%s'".format(arg[0]),
                                    )
                                )
                                break

                            prop_key = arg[2]
                            if prop_key not in entry.custom_properties:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "custom_property '%s' is not found "
                                        "for '%s'".format(prop_key, path),
                                    )
                                )
                                break
                            conn.send(
                                _resp(
                                    "fetch",
                                    0,
                                    entry.get_custom_property(prop_key),
                                )
                            )
                            break

                        if not hasattr(entry, prop):
                            conn.send(
                                _resp(
                                    "fetch",
                                    1,
                                    "unknown property '%s' for '%s'".format(prop, path),
                                )
                            )
                            break
                        conn.send(_resp("fetch", 0, getattr(entry, prop)))
    except CredentialsError:
        print("%s failed to decrypt" % kdbx)
        sys.exit(1)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)
    except ValueError as e:
        print(str(e))
        sys.exit(1)
    except socket.timeout:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        if os.path.exists(sock_path):
            os.remove(sock_path)

        lock_file_ = sock_path + ".lock"
        if os.path.isfile(lock_file_):
            os.remove(lock_file_)


def _rq(cmd, *arg):
    """Request to keepass socket

    :param str cmd: Command name
    :param arg: Arguments
    """
    return "\n".join((cmd, *arg)).encode()


def _resp(cmd, status_code, payload=""):
    """Response from keepass socket

    :param str cmd: Command name
    :param int status_code: == 0 - no error; 1 - an error
    :param payload: A data from keepass or error description
    """
    return "\n".join((cmd, str(status_code), str(payload))).encode()


def _keepass_socket_path(dbx_path):
    # UNIX socket path for a dbx (supported multiple dbx)
    tempdir = tempfile.gettempdir()
    if not os.access(tempdir, os.W_OK):
        raise AnsibleError("KeePass: no write permissions to '%s'" % tempdir)

    suffix = hashlib.sha1(("%s%s" % (getpass.getuser(), dbx_path)).encode()).hexdigest()
    return "%s/ansible-keepass-%s.sock" % (tempdir, suffix[:8])


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("kdbx", type=str)
    arg_parser.add_argument("kdbx_sock", type=str, nargs="?", default=None)
    arg_parser.add_argument("ttl", type=int, nargs="?", default=0)
    arg_parser.add_argument("--key", type=str, nargs="?", default=None)
    arg_parser.add_argument("--ask-pass", action=argparse.BooleanOptionalAction)
    args = arg_parser.parse_args()

    kdbx = os.path.realpath(os.path.expanduser(os.path.expandvars(args.kdbx)))
    if args.key:
        key = os.path.realpath(os.path.expanduser(os.path.expandvars(args.key)))
    else:
        key = None

    if args.kdbx_sock:
        kdbx_sock = args.kdbx_sock
    else:
        kdbx_sock = _keepass_socket_path(kdbx)

    password = None
    if args.ask_pass:
        password = getpass.getpass("Password: ")
        if isinstance(password, bytes):
            password = password.decode(sys.stdin.encoding)

    lock_file = kdbx_sock + ".lock"
    if not os.path.isfile(lock_file):
        open(lock_file, 'a').close()

    _keepass_socket(kdbx, key, kdbx_sock, args.ttl, password)
