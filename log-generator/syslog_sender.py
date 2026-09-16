"""
Syslog Sender — TCP and UDP

Sends raw log lines to any syslog receiver:
SC4S, rsyslog, syslog-ng, etc.

TCP: persistent connection with automatic reconnect on failure.
UDP: persistent socket (fire-and-forget, no connection state).
"""

import socket


class SyslogSender:

    def __init__(self, host: str, port: int, protocol: str = 'udp'):
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower()
        self._sock = None
        self._connect()

    def _connect(self) -> None:
        if self.protocol == 'tcp':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.host, self.port))
            s.settimeout(None)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = s

    def send_event(self, event_data: str) -> bool:
        msg = (event_data + '\n').encode('utf-8')
        try:
            if self.protocol == 'tcp':
                if self._sock is None:
                    self._connect()
                self._sock.sendall(msg)
            else:
                self._sock.sendto(msg, (self.host, self.port))
            return True
        except Exception as e:
            print(f"[Syslog] Send error ({self.host}:{self.port}/{self.protocol.upper()}): {e}")
            if self.protocol == 'tcp':
                self._reset_tcp()
            return False

    def _reset_tcp(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
        self._sock = None

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
