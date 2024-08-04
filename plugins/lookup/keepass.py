__metaclass__ = type

import argparse
import getpass
import hashlib
import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <viczem.dev@gmail.com>
    version_added: '0.7.5'
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
      - "{{ lookup('keepass', 'path/to/entry', 'custom_properties', 'my_prop_name') }}"
      - "{{ lookup('keepass', 'path/to/entry', 'attachments', 'my_file_name') }}"
      - "{{ lookup('keepass', 'entry', 'username') }}"
      - "{{ lookup('keepass', 'entry', 'password', regex=true) }}"
      - "{{ lookup('keepass', 'entry', 'password', url='github.com', regex=true) }}"
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
        if not var_key and "ANSIBLE_KEEPASS_KEY_FILE" in os.environ:
            var_key = os.environ.get('ANSIBLE_KEEPASS_KEY_FILE')

        if var_key:
            var_key = os.path.realpath(os.path.expanduser(os.path.expandvars(var_key)))
            if not os.path.isfile(var_key):
                raise AnsibleError("KeePass: '%s' is not found" % var_key)

        # Check password (optional)
        var_psw = self._var(variables_.get("keepass_psw", ""))

        if not var_psw and "ANSIBLE_KEEPASS_PSW" in os.environ:
            var_psw = os.environ.get('ANSIBLE_KEEPASS_PSW')

        if not var_key and not var_psw:
            raise AnsibleError("KeePass: 'keepass_psw' and/or 'keepass_key' is not set")

        # TTL of keepass socket (optional, default: 60 seconds)
        default_ttl = "60"
        if "ANSIBLE_KEEPASS_TTL" in os.environ:
            default_ttl = os.environ.get("ANSIBLE_KEEPASS_TTL")
        var_ttl = self._var(str(variables_.get("keepass_ttl", default_ttl)))

        socket_path = _keepass_socket_path(var_dbx)
        lock_file_ = socket_path + ".lock"

        try:
            os.open(lock_file_, os.O_RDWR)
        except FileNotFoundError:
            cmd = [
                sys.executable,
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
            return []
        else:
            # Fetching data from the keepass socket
            return self._send(socket_path, "fetch", terms, **kwargs)

    def _send(self, kp_soc, cmd, terms, **kwargs):

        display.vvv("KeePass: connect to '%s'" % kp_soc)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            sock.connect(kp_soc)
        except FileNotFoundError:
            raise AnsibleError("KeePass: '%s' is not found" % kp_soc)

        try:
            display.vvv("KeePass: %s %s" % (cmd, terms))
            sock.send(_rq(cmd, *terms, **kwargs))

            data = b''
            while True:
                _ = sock.recv(1024)
                data += _
                if len(_) < 1024:
                    break

            resp = data.decode().splitlines()
            resp_len = len(resp)
            if resp_len == 0:
                raise AnsibleError("KeePass: '%s' result is empty" % cmd)

            if resp_len >= 3:
                if resp[0] != cmd:
                    raise AnsibleError(
                        "KeePass: received command '%s', expected '%s'" % (resp[0], cmd)
                    )
                if resp[1] == "0":
                    return [os.linesep.join(resp[2:])]
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
    tmp_files = []
    try:
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

                        rq = json.loads(data)
                        if len(rq) == 0:
                            conn.send(_resp("", 1, "empty request"))
                            break

                        cmd, arg, kwargs = rq['cmd'], rq['arg'], rq['kwargs']
                        arg_len = len(arg)

                        # CMD: quit | exit | close
                        if arg_len == 0 and cmd in ("quit", "exit", "close"):
                            conn.send(_resp(cmd, 0))
                            conn.close()
                            is_open = False
                            break

                        # CMD: password
                        if kp is None:
                            if cmd == "password" and arg_len > 0:
                                kp = PyKeePass(kdbx, arg[0], kdbx_key)
                                conn.send(_resp("password", 0))
                                break
                            elif cmd == "password" and kdbx_key:
                                kp = PyKeePass(kdbx, None, kdbx_key)
                                conn.send(_resp("password", 0))
                                break
                            else:
                                conn.send(_resp("password", 1))
                                break
                        elif cmd == "password":
                            conn.send(_resp("password", 0))
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
                        if 'first' not in kwargs:
                            kwargs['first'] = True
                        if len(path) > 1:
                            entry = kp.find_entries(path=path, **kwargs)
                        elif len(path) == 1:
                            entry = kp.find_entries(title=path[0], **kwargs)
                        else:
                            entry = kp.find_entries(**kwargs)

                        if entry is None:
                            conn.send(
                                _resp("fetch", 1, "path '%s' is not found" % path)
                            )
                            break

                        prop = arg[1]
                        if prop == "custom_properties":
                            if arg_len == 2:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "no custom_property key for '%s'" % arg[0],
                                    )
                                )
                                break

                            prop_key = arg[2]
                            if prop_key not in entry.custom_properties:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "custom_property '%s' is not found for '%s'"
                                        "" % (prop_key, path),
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
                        if prop == "attachments":
                            if arg_len == 2:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "attachment key is not set for '%s'" % arg[0],
                                    )
                                )
                                break

                            prop_key = arg[2]
                            attachment = None
                            for _ in entry.attachments:
                                if _.filename == prop_key:
                                    attachment = _
                                    break
                            if attachment is None:
                                conn.send(
                                    _resp(
                                        "fetch",
                                        1,
                                        "attachment '%s' is not found "
                                        "for '%s'" % (prop_key, path),
                                    )
                                )
                                break

                            tmp_file = tempfile.mkstemp(f".{attachment.filename}")[1]
                            with open(tmp_file, "wb") as f:
                                f.write(attachment.data)
                            tmp_files.append(tmp_file)
                            conn.send(_resp("fetch", 0, tmp_file))
                            break

                        if not hasattr(entry, prop):
                            conn.send(
                                _resp(
                                    "fetch",
                                    1,
                                    "unknown property '%s' for '%s'" % (prop, path),
                                )
                            )
                            break
                        conn.send(_resp("fetch", 0, entry.deref(prop)))
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
        for tmp_file in tmp_files:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        if os.path.exists(sock_path):
            os.remove(sock_path)

        lock_file_ = sock_path + ".lock"
        if os.path.isfile(lock_file_):
            os.remove(lock_file_)


def _rq(cmd, *arg, **kwargs):
    """Request to keepass socket

    :param str cmd: Command name
    :param arg: Arguments
    """
    return json.dumps({'cmd': cmd, 'arg': arg, 'kwargs': kwargs}).encode()


def _resp(cmd, status_code, payload=""):
    """Response from keepass socket

    :param str cmd: Command name
    :param int status_code: == 0 - no error; 1 - an error
    :param payload: A data from keepass or error description
    """
    return "\n".join((cmd, str(status_code), str(payload))).encode()


def _keepass_socket_path(dbx_path):
    # UNIX socket path for a dbx (supported multiple dbx)
    if "ANSIBLE_KEEPASS_SOCKET" in os.environ:
        return os.environ.get('ANSIBLE_KEEPASS_SOCKET')
    # else:
    tempdir = tempfile.gettempdir()
    if not os.access(tempdir, os.W_OK):
        raise AnsibleError("KeePass: no write permissions to '%s'" % tempdir)

    suffix = hashlib.sha1(("%s%s" % (getpass.getuser(), dbx_path)).encode()).hexdigest()
    return "%s/ansible-keepass-%s.sock" % (tempdir, suffix[:8])


def lock(kdbx_sock_path):
    fd = os.open(kdbx_sock_path + ".lock", os.O_RDWR | os.O_CREAT | os.O_TRUNC)

    try:
        # The LOCK_EX means that only one process can hold the lock
        # The LOCK_NB means that the fcntl.flock() is not blocking
        # https://docs.python.org/3/library/fcntl.html#fcntl.flock
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        return None

    return fd


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("kdbx", type=str)
    arg_parser.add_argument("kdbx_sock", type=str, nargs="?", default=None)
    arg_parser.add_argument("ttl", type=int, nargs="?", default=0)
    arg_parser.add_argument("--key", type=str, nargs="?", default=None)
    arg_parser.add_argument("--ask-pass", action="store_true")
    args = arg_parser.parse_args()

    arg_kdbx = os.path.realpath(os.path.expanduser(os.path.expandvars(args.kdbx)))
    if args.key:
        arg_key = os.path.realpath(os.path.expanduser(os.path.expandvars(args.key)))
    else:
        arg_key = None

    if args.kdbx_sock:
        arg_kdbx_sock = args.kdbx_sock
    else:
        arg_kdbx_sock = _keepass_socket_path(arg_kdbx)

    password = None
    if args.ask_pass:
        password = getpass.getpass("Password: ")
        if isinstance(password, bytes):
            password = password.decode(sys.stdin.encoding)
    elif "ANSIBLE_KEEPASS_PSW" in os.environ:
        password = os.environ.get('ANSIBLE_KEEPASS_PSW')

    arg_ttl = args.ttl
    if arg_ttl is None and "ANSIBLE_KEEPASS_TTL" in os.environ:
        arg_ttl = os.environ.get('ANSIBLE_KEEPASS_TTL')

    os.umask(0o177)
    if lock(arg_kdbx_sock):
        _keepass_socket(arg_kdbx, arg_key, arg_kdbx_sock, arg_ttl, password)
