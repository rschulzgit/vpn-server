"""Selbst-Update der Anwendung aus dem GitHub-Repository.

Ablauf (in einer eigenen systemd-Unit, damit der Neustart der Weboberflaeche
das Update nicht abbricht):

1. Stand ermitteln (neuestes Release oder Branch-Spitze) und herunterladen
2. Pruefen (Pflichtdateien, Python-Syntax, Import-Test)
3. Bisherigen Stand sichern (Anwendung + systemd-Units)
4. ``installer/install.sh --upgrade`` des neuen Stands ausfuehren
   (neue Pakete, Dienste, Anwendung; danach Konfiguration anwenden)
5. Funktionspruefung der Weboberflaeche - schlaegt sie fehl, wird der
   vorherige Stand automatisch wiederhergestellt.

Zustand, Clients und Schluessel (/etc/vpn-server) bleiben unberuehrt.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__, util

APP_DIR = "/opt/vpn-server"
INSTALLED_FILE = APP_DIR + "/INSTALLED.json"
WORK_DIR = "/var/lib/vpn-server/update"
BACKUP_DIR = WORK_DIR + "/previous"
STATUS_FILE = WORK_DIR + "/status.json"
LOG_FILE = "/var/log/vpn-server-app-update.log"
UNIT = "vpn-app-update"
DEFAULT_REPO = "rschulzgit/vpn-server"
DEFAULT_API = "https://api.github.com"
MAX_TARBALL = 60 * 1024 * 1024
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
REQUIRED = ("vpnserver/__init__.py", "vpnserver/cli.py", "vpnserver/web/__init__.py",
            "installer/install.sh", "installer/systemd/vpn-webui.service")


class UpdateError(Exception):
    pass


# --------------------------------------------------------------------------
# Einstellungen und installierter Stand
# --------------------------------------------------------------------------

def installed() -> dict:
    try:
        info = json.loads(util.read_file(INSTALLED_FILE) or "{}")
    except ValueError:
        info = {}
    info.setdefault("version", __version__)
    info.setdefault("sha", "")
    info.setdefault("ref", "")
    return info


def settings(state: dict) -> dict:
    u = state.setdefault("update", {})
    inst = installed()
    u.setdefault("repo", DEFAULT_REPO)
    u.setdefault("api", DEFAULT_API)
    u.setdefault("token", "")
    u.setdefault("auto", False)
    u.setdefault("available", {})
    u.setdefault("last_check", "")
    # Standard: veroeffentlichte Releases des oeffentlichen Repositorys, ohne Token
    if not u.get("channel"):
        u["channel"] = "release"
    if not u.get("branch"):
        ref = inst.get("ref", "")
        u["branch"] = ref if ref and not re.match(r"^v\d", ref) else "main"
    return u


def validate_settings(repo: str, channel: str, branch: str, api: str = DEFAULT_API) -> None:
    if not REPO_RE.match(repo or ""):
        raise UpdateError("Ungültiges Repository (Format: besitzer/name).")
    if channel not in ("release", "branch"):
        raise UpdateError("Ungültiger Kanal.")
    if channel == "branch" and not REF_RE.match(branch or ""):
        raise UpdateError("Ungültiger Branch-Name.")
    if not re.match(r"^https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._/-]*)?$", api or ""):
        raise UpdateError("Ungültige API-Adresse.")


def _vtuple(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v.lstrip("v")))


# --------------------------------------------------------------------------
# GitHub-API
# --------------------------------------------------------------------------

def _request(u: dict, path: str, accept: str = "application/vnd.github+json", stream: bool = False):
    url = u.get("api", DEFAULT_API).rstrip("/") + path
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "vpn-server-updater",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    if u.get("token"):
        req.add_header("Authorization", "Bearer " + u["token"])
    try:
        resp = urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context())
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise UpdateError("Zugriff verweigert: Das GitHub-Token ist ungültig, abgelaufen oder hat "
                              "keine Leserechte für das Repository.") from None
        if exc.code == 404:
            raise UpdateError("Nicht gefunden. Repository bzw. Branch prüfen (ein privates Repository "
                              "benötigt ein GitHub-Token).") from None
        raise UpdateError(f"GitHub antwortet mit Fehler {exc.code}.") from None
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"GitHub ist nicht erreichbar: {getattr(exc, 'reason', exc)}") from None
    if stream:
        return resp
    with resp:
        return resp.read()


def _json(u: dict, path: str) -> dict:
    try:
        return json.loads(_request(u, path))
    except ValueError:
        raise UpdateError("Unerwartete Antwort von GitHub.") from None


def check(state: dict) -> dict:
    """Ermittelt den verfuegbaren Stand und merkt ihn im Zustand vor."""
    u = settings(state)
    repo = u["repo"]
    if u["channel"] == "release":
        try:
            rel = _json(u, f"/repos/{repo}/releases/latest")
        except UpdateError as exc:
            if "Nicht gefunden" in str(exc):
                raise UpdateError("Es wurde noch kein Release veröffentlicht. Alternativ den Kanal "
                                  "„Branch“ wählen.") from None
            raise
        ref = rel.get("tag_name", "")
        notes = rel.get("body") or rel.get("name") or ""
        date = rel.get("published_at", "")
    else:
        ref = u["branch"]
        notes = date = ""
    commit = _json(u, f"/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}")
    sha = commit.get("sha", "")
    if not re.match(r"^[0-9a-f]{40}$", sha):
        raise UpdateError("Unerwartete Antwort von GitHub (Commit).")
    if u["channel"] == "branch":
        notes = commit.get("commit", {}).get("message", "")
        date = commit.get("commit", {}).get("committer", {}).get("date", "")
    init = _request(u, f"/repos/{repo}/contents/vpnserver/__init__.py?ref={sha}",
                    accept="application/vnd.github.raw").decode(errors="replace")
    m = re.search(r'__version__ = "([^"]+)"', init)
    if not m:
        raise UpdateError("Versionsnummer im Repository nicht gefunden.")
    version = m.group(1)
    inst = installed()
    if u["channel"] == "release":
        newer = _vtuple(version) > _vtuple(inst["version"]) or (
            _vtuple(version) == _vtuple(inst["version"]) and inst.get("sha") not in ("", sha))
    else:
        newer = sha != inst.get("sha")
    avail = {"version": version, "sha": sha, "ref": ref, "notes": notes[:3000], "date": date,
             "newer": newer, "channel": u["channel"]}
    u["available"] = avail
    u["last_check"] = dt.datetime.now().isoformat(timespec="seconds")
    return avail


# --------------------------------------------------------------------------
# Status (fuer die Weboberflaeche)
# --------------------------------------------------------------------------

def status() -> dict:
    try:
        data = json.loads(util.read_file(STATUS_FILE) or "{}")
    except ValueError:
        data = {}
    data.setdefault("state", "idle")
    if data["state"] == "running" and not util.DRYRUN:
        active = util.run(["systemctl", "is-active", "--quiet", UNIT + ".service"]).returncode == 0
        if not active and time.time() - data.get("updated", 0) > 30:
            data["state"] = "failed"
            data["message"] = "Das Update wurde unerwartet beendet (Protokoll prüfen)."
    data["log"] = (util.read_file(LOG_FILE) or "")[-8000:]
    data["backup"] = os.path.isdir(util.P(BACKUP_DIR + "/app"))
    return data


def _set_status(state: str, message: str, **extra) -> None:
    data = {"state": state, "message": message, "updated": time.time(), **extra}
    util.write_file(STATUS_FILE, json.dumps(data, ensure_ascii=False), mode=0o644)
    print(f"[{dt.datetime.now():%H:%M:%S}] {message}", flush=True)


def running() -> bool:
    return status()["state"] == "running"


def start(action: str = "install") -> None:
    """Startet Update oder Wiederherstellung in einer eigenen systemd-Unit."""
    if running():
        raise UpdateError("Es läuft bereits ein Update.")
    if util.DRYRUN:
        return
    os.makedirs(util.P(WORK_DIR), exist_ok=True)
    util.write_file(LOG_FILE, f"=== {dt.datetime.now():%d.%m.%Y %H:%M:%S} – "
                              f"{'Update' if action == 'install' else 'Wiederherstellung'} ===\n", mode=0o640)
    _set_status("running", "Wird gestartet …")
    util.run(["systemctl", "reset-failed", UNIT + ".service"])
    res = util.run(["systemd-run", f"--unit={UNIT}", "--collect",
                    f"--property=StandardOutput=append:{LOG_FILE}",
                    f"--property=StandardError=append:{LOG_FILE}",
                    "/usr/local/sbin/vpnctl", "update", "run" if action == "install" else "run-rollback"])
    if res.returncode != 0:
        _set_status("failed", "Update konnte nicht gestartet werden: " + (res.stderr or "").strip())
        raise UpdateError("Update konnte nicht gestartet werden.")


# --------------------------------------------------------------------------
# Ausfuehrung (laeuft in vpn-app-update.service)
# --------------------------------------------------------------------------

def _download(u: dict, sha: str, dest_dir: str) -> str:
    shutil.rmtree(dest_dir, ignore_errors=True)
    os.makedirs(dest_dir)
    tgz = os.path.join(dest_dir, "source.tar.gz")
    resp = _request(u, f"/repos/{u['repo']}/tarball/{sha}", accept="application/vnd.github+json",
                    stream=True)
    size = 0
    with resp, open(tgz, "wb") as fh:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_TARBALL:
                raise UpdateError("Download zu groß.")
            fh.write(chunk)
    src = os.path.join(dest_dir, "src")
    os.makedirs(src)
    with tarfile.open(tgz, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise UpdateError("Ungültiges Archiv.")
        try:
            tar.extractall(src, filter="data")
        except TypeError:  # Python < 3.11.4
            tar.extractall(src)  # noqa: S202 (Eintraege oben geprueft)
    tops = [d for d in os.listdir(src) if os.path.isdir(os.path.join(src, d))]
    if len(tops) != 1:
        raise UpdateError("Unerwarteter Aufbau des Archivs.")
    return os.path.join(src, tops[0])


def _verify(root: str) -> None:
    for rel in REQUIRED:
        if not os.path.isfile(os.path.join(root, rel)):
            raise UpdateError(f"Im neuen Stand fehlt {rel}.")
    res = subprocess.run([sys.executable, "-m", "compileall", "-q", "-f", os.path.join(root, "vpnserver")],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise UpdateError("Syntaxfehler im neuen Stand: " + (res.stdout + res.stderr)[-400:])
    env = dict(os.environ, PYTHONPATH=root, PYTHONDONTWRITEBYTECODE="1")
    res = subprocess.run([sys.executable, "-c", "import vpnserver.cli, vpnserver.web, vpnserver.apply"],
                         capture_output=True, text=True, env=env)
    if res.returncode != 0:
        raise UpdateError("Neuer Stand lässt sich nicht laden: " + res.stderr[-400:])


def _unit_files() -> list[str]:
    out = []
    base = "/etc/systemd/system"
    for name in sorted(os.listdir(base)):
        if name.startswith("vpn-") and name.endswith((".service", ".timer")) or name == "accel-ppp.service":
            out.append(os.path.join(base, name))
    return out


def _backup() -> None:
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    os.makedirs(BACKUP_DIR + "/units")
    shutil.copytree(APP_DIR, BACKUP_DIR + "/app", symlinks=True)
    for f in _unit_files():
        shutil.copy2(f, BACKUP_DIR + "/units/")


def _restore() -> None:
    if not os.path.isdir(BACKUP_DIR + "/app"):
        raise UpdateError("Keine Sicherung vorhanden.")
    tmp = APP_DIR + ".restore"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(BACKUP_DIR + "/app", tmp, symlinks=True)
    old = APP_DIR + ".failed"
    shutil.rmtree(old, ignore_errors=True)
    os.rename(APP_DIR, old)
    os.rename(tmp, APP_DIR)
    shutil.rmtree(old, ignore_errors=True)
    for f in os.listdir(BACKUP_DIR + "/units"):
        shutil.copy2(os.path.join(BACKUP_DIR + "/units", f), "/etc/systemd/system/")
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["/usr/local/sbin/vpnctl", "apply", "--quiet", "--no-webui-restart"], timeout=600)
    subprocess.run(["systemctl", "restart", "vpn-webui.service"], timeout=120)
    subprocess.run(["systemctl", "restart", "vpn-stats.service"], timeout=60)


def _healthy(port: int, timeout: int = 150) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=5, context=ctx) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(3)
    return False


def run_install() -> int:
    """Fuehrt das Update aus (Einstiegspunkt der systemd-Unit)."""
    from . import state as st
    state = st.load()
    u = settings(state)
    port = int(state["server"].get("webui_port", 8443))
    before = installed()
    try:
        _set_status("running", "Suche den neuesten Stand …")
        avail = check(state)
        _set_status("running", f"Lade Version {avail['version']} ({avail['sha'][:7]}) herunter …")
        root = _download(u, avail["sha"], WORK_DIR + "/new")
        _set_status("running", "Prüfe den neuen Stand …")
        _verify(root)
        _set_status("running", "Sichere den bisherigen Stand …")
        _backup()
    except (UpdateError, OSError) as exc:
        _set_status("failed", f"Update abgebrochen: {exc}")
        return 1
    _set_status("running", "Installiere (Pakete, Dienste, Anwendung) – das kann einige Minuten dauern …")
    res = subprocess.run(["bash", os.path.join(root, "installer", "install.sh"), "--upgrade"], timeout=3600)
    ok = res.returncode == 0
    if ok:
        _set_status("running", "Prüfe die Weboberfläche …")
        ok = _healthy(port)
    if not ok:
        _set_status("running", "Fehler – stelle den bisherigen Stand wieder her …")
        try:
            _restore()
            _set_status("failed", f"Update fehlgeschlagen; Version {before['version']} wurde "
                                  "wiederhergestellt. Details im Protokoll.")
        except (UpdateError, OSError, subprocess.SubprocessError) as exc:
            _set_status("failed", f"Update und Wiederherstellung fehlgeschlagen: {exc}")
        return 1
    info = {"version": avail["version"], "sha": avail["sha"], "ref": avail["ref"],
            "channel": u["channel"], "installed": dt.datetime.now().isoformat(timespec="seconds"),
            "previous": {k: before.get(k, "") for k in ("version", "sha", "ref")}}
    util.write_file(INSTALLED_FILE, json.dumps(info, indent=2) + "\n", mode=0o644)
    with st.locked():
        s = st.load()
        settings(s)
        s["update"]["available"] = dict(avail, newer=False)
        st.save(s)
    shutil.rmtree(WORK_DIR + "/new", ignore_errors=True)
    _set_status("done", f"Version {avail['version']} ({avail['sha'][:7]}) wurde installiert.",
                version=avail["version"])
    return 0


def run_rollback() -> int:
    try:
        prev = json.loads(util.read_file(BACKUP_DIR + "/app/INSTALLED.json") or "{}")
    except ValueError:
        prev = {}
    try:
        _set_status("running", "Stelle die vorherige Version wieder her …")
        _restore()
    except (UpdateError, OSError, subprocess.SubprocessError) as exc:
        _set_status("failed", f"Wiederherstellung fehlgeschlagen: {exc}")
        return 1
    _set_status("done", f"Version {prev.get('version', '(vorherige)')} wurde wiederhergestellt.")
    return 0


def maybe_auto_update(state: dict) -> str:
    """Taegliche Wartung: pruefen und - falls eingeschaltet - automatisch installieren."""
    u = settings(state)
    try:
        avail = check(state)
    except UpdateError as exc:
        return f"Update-Prüfung: {exc}"
    if avail["newer"] and u.get("auto"):
        try:
            start("install")
            return f"Automatisches Update auf {avail['version']} gestartet."
        except UpdateError as exc:
            return str(exc)
    return "Update verfügbar." if avail["newer"] else "Aktuell."
