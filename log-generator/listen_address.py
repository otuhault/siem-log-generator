"""Where to serve, and whether anything already holds the port.

Werkzeug reports a busy port only after it fails to bind, with a message that
cannot mention this application's own option:

    Port 5002 is in use by another program. Either identify and stop that
    program, or start the server with a different port.

"Identify that program" is the hard part, and on macOS it is often impossible
as written: `lsof` shows only the current user's processes, so a port held by
another account, or by a root daemon, reads as "nothing is running on 5002".
This module looks before binding, names the holder when it can see one, and
says plainly when it cannot — which is the case that leaves people stuck.

It also decides the address. The default is loopback: this application has no
authentication, and /api/configurations hands back HEC tokens in clear text, so
binding every interface publishes them to whatever shares the network. That is
still available with --host, deliberately and with a warning, because reaching
the interface from another machine is a real thing to want.
"""

import argparse
import errno
import os
import socket
import subprocess

DEFAULT_PORT = 5002

#: Loopback only. The application has no authentication of any kind, and
#: /api/configurations returns HEC tokens in clear text, so anything that can
#: reach the port can read them and drive the generator. Serving the whole
#: network has to be asked for, not inherited.
DEFAULT_HOST = '127.0.0.1'

#: Addresses that reach no further than this machine.
LOCAL_HOSTS = {'127.0.0.1', 'localhost', '::1'}

#: Honoured when no flag is given, so a launcher can set these once.
PORT_ENV = 'LOG_GENERATOR_PORT'
HOST_ENV = 'LOG_GENERATOR_HOST'


def _arguments(argv):
    """`--port` and `--host` as given, ignoring whatever else is on the line.

    Flask and pytest both pass arguments of their own, so unknown ones are left
    alone rather than turned into a usage error.
    """
    parser = argparse.ArgumentParser(
        prog='app.py', add_help=True,
        description='SIEM Log Generator — web interface.')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help=f'TCP port to listen on (default: {DEFAULT_PORT}, '
                             f'or ${PORT_ENV})')
    parser.add_argument('-H', '--host', default=None,
                        help=f'address to bind (default: {DEFAULT_HOST}, or '
                             f'${HOST_ENV}). 0.0.0.0 serves the whole network, '
                             f'with no authentication in front of it.')
    known, _unknown = parser.parse_known_args(argv)
    return known


def parse_port(argv=None, environ=None):
    """The port asked for, from `-p/--port`, else the environment, else 5002.

    Raises SystemExit with a usable message on a port that is not a number or
    not in range, rather than letting it surface as a socket error later.
    """
    environ = os.environ if environ is None else environ
    port = _arguments(argv).port
    if port is None:
        raw = (environ.get(PORT_ENV) or '').strip()
        if raw:
            try:
                port = int(raw)
            except ValueError:
                raise SystemExit(f"{PORT_ENV}={raw!r} is not a number.")
    if port is None:
        port = DEFAULT_PORT

    if not 1 <= port <= 65535:
        raise SystemExit(f"Port {port} is out of range — pick one between 1 and 65535.")
    return port


def describe_lsof(output):
    """One line describing the first process in `lsof -F` output, or None.

    `-F` prints one field per line, tagged by its first character: `p` for the
    pid, `c` for the command, `L` for the login name. Kept apart from running
    lsof so it can be tested against output this machine would not produce —
    the field set differs between the macOS, Linux and BSD builds.
    """
    pid = command = user = None
    for line in (output or '').splitlines():
        tag, value = line[:1], line[1:]
        if tag == 'p' and pid is None:
            pid = value
        elif tag == 'c' and command is None:
            command = value
        elif tag == 'L' and user is None:
            user = value
    if not pid:
        return None
    who = f' owned by {user}' if user else ''
    return f'{command or "a process"} (PID {pid}){who}'


def parse_host(argv=None, environ=None):
    """The address to bind, from `-H/--host`, else the environment, else loopback."""
    environ = os.environ if environ is None else environ
    host = _arguments(argv).host
    if host is None:
        host = (environ.get(HOST_ENV) or '').strip() or None
    return host or DEFAULT_HOST


def is_local(host):
    """Does this address reach anything but this machine?"""
    return host in LOCAL_HOSTS


def lan_address():
    """This machine's address on its network, for the warning. None if offline.

    Asks the routing table which source address would be used to reach the
    outside; the socket is never connected, so nothing leaves the machine.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.2)
            probe.connect(('192.0.2.1', 9))    # TEST-NET-1, routed nowhere
            return probe.getsockname()[0]
    except Exception:
        # Offline, no route, or a test harness that forbids sockets. This only
        # decorates a warning; failing here must not stop the server.
        return None


def exposure_warning(host, port, address=None):
    """What binding beyond loopback actually means, said before it happens."""
    address = address or lan_address() or '<this machine>'
    return '\n'.join([
        f'WARNING: serving on {host} — reachable from your whole network.',
        '',
        f'  Anyone who can reach http://{address}:{port} can read your HEC',
        '  tokens and drive the generator. There is no authentication.',
        '',
        '  The interactive debugger is switched off while the server is not',
        f'  local. Drop --host to go back to {DEFAULT_HOST}.',
    ])


def port_holder(port):
    """A one-line description of what holds `port`, or None if nothing is visible.

    None means only that nothing could be seen: `lsof` may be absent, or the
    holder may belong to another user. The caller must not turn that into
    "the port is free".
    """
    try:
        found = subprocess.run(
            ['lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN', '-F', 'pcnL'],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if found.returncode != 0:
        return None
    return describe_lsof(found.stdout)


def is_free(port, host=DEFAULT_HOST):
    """Can we actually bind it? The only question that decides whether we start.

    Asked about the address we are going to bind, not a fixed one: on BSD a
    listener on 0.0.0.0 does not stop a later bind to 127.0.0.1, so probing the
    wildcard would refuse a port the server would have taken quite happily.

    SO_REUSEADDR matches what Werkzeug itself asks for, so a socket in
    TIME_WAIT does not read as busy here and then bind fine a moment later.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as error:
            if error.errno in (errno.EADDRINUSE, errno.EACCES):
                return False
            raise
    return True


def busy_message(port, holder, script='./start.sh'):
    """What to print when the port is taken. Every line is something to do."""
    lines = [f'Port {port} is already in use.', '']
    if holder:
        lines += [f'  Held by: {holder}', '']
    else:
        lines += [
            '  Nothing visible is holding it, which usually means the process',
            '  belongs to another user — lsof only shows your own. Try:',
            f'      sudo lsof -nP -iTCP:{port} -sTCP:LISTEN',
            '']
    lines += [
        'Either free it:',
        '      ./stop.sh' + (f' -p {port}' if port != DEFAULT_PORT else ''),
        '',
        'or serve on another port:',
        f'      {script} -p {port + 3}',
    ]
    return '\n'.join(lines)


def resolve(argv=None, environ=None, script='./start.sh', warn=print):
    """(host, port) to serve on, or exit with something the reader can act on.

    Warns on the way out when the address is not loopback, rather than leaving
    the reader to notice a second URL in Flask's banner and wonder.
    """
    host = parse_host(argv, environ)
    port = parse_port(argv, environ)
    if not is_free(port, host):
        raise SystemExit(busy_message(port, port_holder(port), script))
    if not is_local(host):
        warn(exposure_warning(host, port))
    return host, port
