#!/usr/bin/env python3
"""Nachbildung der GitHub-API-Endpunkte, die das Selbst-Update nutzt.

Liefert den aktuellen Arbeitsstand des Repositorys (git ls-files) als neuen
Stand mit geaenderter Versionsnummer - wie ein privates Repository nur mit
gueltigem Token.

    fake_github.py --port 8097 --repo-dir . --version 9.9.9 --token geheim
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import io
import json
import os
import re
import subprocess
import tarfile
import threading
import time


def build_tarball(repo_dir: str, prefix: str, version: str) -> bytes:
    files = subprocess.run(["git", "-c", "safe.directory=*", "-C", repo_dir, "ls-files"], capture_output=True, text=True,
                           check=True).stdout.split("\n")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in files:
            path = os.path.join(repo_dir, rel)
            if not rel or not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            if rel == "vpnserver/__init__.py":
                data = re.sub(rb'__version__ = "[^"]+"', b'__version__ = "' + version.encode() + b'"', data)
            info = tarfile.TarInfo(f"{prefix}/{rel}")
            info.size = len(data)
            info.mode = os.stat(path).st_mode & 0o777
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeGitHub:
    def __init__(self, repo_dir: str, version: str, token: str = "", repo: str = "test/vpn-server",
                 branch: str = "main", release: bool = False):
        self.repo, self.branch, self.version, self.token, self.release = repo, branch, version, token, release
        self.sha = hashlib.sha1(f"{version}{time.time()}".encode()).hexdigest()
        self.tarball = build_tarball(repo_dir, f"{repo.replace('/', '-')}-{self.sha[:7]}", version)
        with open(os.path.join(repo_dir, "vpnserver", "__init__.py"), "rb") as fh:
            self.init = re.sub(rb'__version__ = "[^"]+"', b'__version__ = "' + version.encode() + b'"', fh.read())
        self.requests: list[str] = []

    def handler(self):
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, code, body, ctype="application/json"):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                fake.requests.append(self.path)
                if fake.token and self.headers.get("Authorization") != f"Bearer {fake.token}":
                    return self.send(404, {"message": "Not Found"})
                base = f"/repos/{fake.repo}"
                path = self.path.split("?")[0]
                commit = {"sha": fake.sha, "commit": {"message": f"Testversion {fake.version}",
                                                      "committer": {"date": "2026-11-06T12:00:00Z"}}}
                if path in (f"{base}/commits/{fake.branch}", f"{base}/commits/{fake.sha}",
                            f"{base}/commits/v{fake.version}"):
                    return self.send(200, commit)
                if path == f"{base}/contents/vpnserver/__init__.py":
                    return self.send(200, fake.init, "text/plain")
                if path == f"{base}/tarball/{fake.sha}":
                    return self.send(200, fake.tarball, "application/x-gzip")
                if path == f"{base}/releases/latest" and fake.release:
                    return self.send(200, {"tag_name": f"v{fake.version}", "name": f"Version {fake.version}",
                                           "body": "Testrelease", "published_at": "2026-11-06T12:00:00Z"})
                return self.send(404, {"message": "Not Found"})
        return Handler

    def serve(self, port: int, host: str = "127.0.0.1", background: bool = False):
        srv = http.server.ThreadingHTTPServer((host, port), self.handler())
        if background:
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            return srv
        srv.serve_forever()
        return srv


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8097)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--repo-dir", default=".")
    ap.add_argument("--version", default="9.9.9")
    ap.add_argument("--token", default="")
    ap.add_argument("--release", action="store_true")
    args = ap.parse_args()
    fake = FakeGitHub(args.repo_dir, args.version, args.token, release=args.release)
    print(f"Fake-GitHub: test/vpn-server@{fake.sha[:7]} Version {args.version} auf {args.host}:{args.port}",
          flush=True)
    fake.serve(args.port, args.host)


if __name__ == "__main__":
    main()
