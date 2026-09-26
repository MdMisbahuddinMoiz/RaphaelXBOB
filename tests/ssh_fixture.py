"""Local SSH test fixture — a real, in-process SSH server on loopback.

Used to validate the governed SSH session capability end to end
WITHOUT touching any external host: a genuine SSH transport, genuine
password authentication, a genuine exec channel, and a genuine exit
status, all on 127.0.0.1 with an ephemeral port.

Deliberately harmless. It executes a fixed, read-only command table
(`ls`, `id`, `whoami`, `pwd`, `uname -a`) against an in-memory
directory listing and returns canned output. It has no shell, no
filesystem access, and no ability to run anything the fixture author did
not write down.

The host key is generated in memory on every run and never written to
disk, so the fixture has no persistent identity to steal or reuse.
"""
from __future__ import annotations

import io
import socket
import threading
from typing import Dict, List, Optional, Tuple

import paramiko

#: The only credential this fixture accepts. A test constant, never a
#: real secret, and never persisted by the SSH capability.
FIXTURE_USERNAME = "rag"
FIXTURE_PASSWORD = "fixture-password-not-a-real-secret"

#: A small, read-only command table. Anything else is refused.
_COMMANDS: Dict[str, bytes] = {
    "ls": b"bin  boot  dev  etc  home  root  tmp  var\n",
    "id": b"uid=1000(rag) gid=1000(rag) groups=1000(rag)\n",
    "whoami": b"rag\n",
    "pwd": b"/home/rag\n",
    "uname -a": b"Linux target 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 "
              b"i686 GNU/Linux\n",
}

#: Commands that produce output on stderr with a non-zero exit.
_FAILING: Dict[str, Tuple[bytes, int]] = {
    "cat /etc/shadow": (b"cat: /etc/shadow: Permission denied\n", 1),
}

#: How large each command's output is when a test wants to prove the
#: bound. Deliberately large.
_VERBOSE = b"X" * 20000


class _Server(paramiko.ServerInterface):
    """Minimal SSH server: password auth + exec channel only."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.command: Optional[str] = None
        self.channel = None
        self.exec_event = threading.Event()

    # -- authentication ------------------------------------------------
    def get_allowed_auths(self, username):  # noqa: D102 - paramiko API
        return "password"

    def check_auth_password(self, username, password):  # noqa: D102
        if username == FIXTURE_USERNAME and password == FIXTURE_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):  # noqa: D102
        return paramiko.AUTH_FAILED

    # -- channels ------------------------------------------------------
    def check_channel_request(self, kind, chanid):  # noqa: D102
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):  # noqa: D102
        """Record ONE allow-listed command and hand off the response.

        paramiko expects the request hook to return promptly; writing
        and closing inside it races the transport teardown. So this only
        records the command and signals, and `_session` performs the
        write from the accept loop.
        """
        self.command = command.decode("utf-8", "replace") if isinstance(
            command, bytes) else str(command)
        self.channel = channel
        self.exec_event.set()
        return True

    def check_port_forward_request(self, *args, **kwargs):  # noqa: D102
        # Refuse ALL forwarding: no secondary destination is reachable.
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, *args, **kwargs):  # noqa: D102
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def _respond(channel, stdout: bytes, stderr: bytes, code: int) -> None:
    """Write bounded output and an exit status, then close the channel."""
    try:
        if stdout:
            channel.sendall(stdout)
        if stderr:
            channel.sendall_stderr(stderr)
        channel.send_exit_status(code)
    except (OSError, paramiko.SSHException):
        pass
    finally:
        try:
            channel.close()
        except (OSError, paramiko.SSHException):
            pass


class LocalSshServer:
    """A real SSH server bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._host = host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._key = paramiko.RSAKey.generate(2048)
        self._stop = False
        #: Per-connection state. A shared instance would carry a stale
        #: `exec_event` into the next connection, so the second command
        #: would never be served.
        self.servers: List[_Server] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.connections: List[str] = []

    @property
    def host_key(self) -> paramiko.RSAKey:
        """In-memory host key. The client fixture uses this directly."""
        return self._key

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _addr = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._session, args=(conn,),
                             daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        transport = None
        server = _Server()
        self.servers.append(server)
        try:
            transport = paramiko.Transport(conn)
            transport.add_server_key(self._key)
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is not None:
                self.connections.append("session")
            if server.exec_event.wait(20) and server.channel:
                _respond(server.channel,
                         *self._response_for(server.command or ""))
            # Keep the transport alive long enough for the client to
            # drain the channel and read the exit status.
            for _ in range(150):
                if self._stop or not transport.is_active():
                    break
                threading.Event().wait(0.1)
        except (paramiko.SSHException, OSError, EOFError):
            pass
        finally:
            if transport is not None:
                try:
                    transport.close()
                except (OSError, paramiko.SSHException):
                    pass
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _response_for(text: str) -> Tuple[bytes, bytes, int]:
        """The fixed, read-only reply for one allow-listed command."""
        if text in _COMMANDS:
            return _COMMANDS[text], b"", 0
        if text in _FAILING:
            out, code = _FAILING[text]
            return b"", out, code
        if text == "cat /var/log/messages":
            return _VERBOSE, b"", 0
        if text == "boom":
            return b"", b"command failed\n", 3
        return b"", b"sh: command not found\n", 127

    def __enter__(self) -> "LocalSshServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop = True
        self._thread.join(timeout=3)
        try:
            self._sock.close()
        except OSError:
            pass


__all__ = [
    "FIXTURE_PASSWORD",
    "FIXTURE_USERNAME",
    "LocalSshServer",
]
