"""Startet die Weboberflaeche mit gunicorn (TLS)."""

from __future__ import annotations

import os
import socket

from gunicorn.app.base import BaseApplication

from .. import pki, state as st, util
from . import create_app


class _App(BaseApplication):
    """gunicorn-Anwendung. Die Optionen werden bei jedem (Neu-)Laden aus dem
    Zustand gelesen, damit ein HUP-Reload neue Zertifikate (z. B. nach einer
    Aenderung der oeffentlichen Adresse oder Let's Encrypt) ohne Unterbrechung
    uebernimmt."""

    def __init__(self, app):
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in _options().items():
            self.cfg.set(key, value)

    def load(self):
        return self.application


def _bind(port: int) -> list[str]:
    if util.ipv6_available():
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.close()
            return [f"[::]:{port}"]  # Dual-Stack (IPv4 + IPv6)
        except OSError:
            pass
    return [f"0.0.0.0:{port}"]


def _options() -> dict:
    state = st.load()
    cert, key = pki.tls_cert_paths(state)
    return {
        "bind": _bind(int(state["server"].get("webui_port", 8443))),
        "workers": 1,
        "threads": 8,
        "worker_class": "gthread",
        "timeout": 300,
        "certfile": util.P(cert),
        "keyfile": util.P(key),
        "accesslog": "-" if os.environ.get("VPNSERVER_ACCESSLOG") else None,
        "errorlog": "-",
        "loglevel": "warning",
        "proc_name": "vpn-webui",
        "forwarded_allow_ips": "",
        "graceful_timeout": 30,
    }


def main() -> None:
    _App(create_app()).run()


if __name__ == "__main__":
    main()
