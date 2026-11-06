"""Weboberflaeche (Flask)."""

from __future__ import annotations

import datetime as dt
import hmac
import ipaddress
import re
import secrets
import threading
import time

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)

from .. import (__version__, apply as ap, pki, profiles, state as st, stats, status, system, tools,
               updater, util, vlan)
from ..state import PROTOCOL_LABELS, PROTOCOLS

PUBLIC_ENDPOINTS = {"login", "static", "share", "share_download", "ca_download", "health"}
SETUP_ENDPOINTS = {"setup", "logout", "detect_ip", "ca_download"}
SHARE_HOURS = 24

_login_failures: dict[str, list] = {}
_fail_lock = threading.Lock()


def create_app() -> Flask:
    app = Flask(__name__)
    try:
        secret = st.load()["secret_key"]
    except FileNotFoundError:
        secret = secrets.token_hex(32)
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_NAME="vpnserver_session",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8),
        MAX_CONTENT_LENGTH=20 * 1024 * 1024,
        TEMPLATES_AUTO_RELOAD=False,
    )

    # ------------------------------------------------------------------
    # Hilfen
    # ------------------------------------------------------------------

    def get_state() -> dict:
        if "state" not in g:
            g.state = st.load()
        return g.state

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals.update(
        csrf_token=csrf_token, PROTOCOL_LABELS=PROTOCOL_LABELS, PROTOCOLS=PROTOCOLS,
        version=__version__, enabled=st.enabled)

    def client_ip() -> str:
        return request.remote_addr or "?"

    def modify(fn):
        """Fuehrt fn(state) unter Sperre aus, wendet an und speichert."""
        with st.locked():
            state = st.load()
            result = fn(state)
            ap.apply(state)
            st.save(state)
        g.state = state
        return result

    @app.before_request
    def guard():
        if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
            return None
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify(error="nicht angemeldet"), 401
            return redirect(url_for("login", next=request.path))
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not token or not hmac.compare_digest(token, session.get("csrf", "")):
                abort(400, "Ungültiges CSRF-Token - bitte Seite neu laden.")
        state = get_state()
        needs_setup = state["admin"].get("must_change") or not state["server"].get("setup_done")
        if needs_setup and request.endpoint not in SETUP_ENDPOINTS:
            return redirect(url_for("setup"))
        return None

    @app.after_request
    def headers(resp: Response):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(404)
    def error_page(err):
        return render_template("error.html", error=err), err.code

    # ------------------------------------------------------------------
    # Anmeldung
    # ------------------------------------------------------------------

    @app.route("/health")
    def health():
        return "ok"

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        ip = client_ip()
        if request.method == "POST":
            with _fail_lock:
                fails, until = _login_failures.get(ip, [0, 0.0])
            if until > time.time():
                error = f"Zu viele Fehlversuche. Bitte {int(until - time.time()) + 1} s warten."
            else:
                state = get_state()
                user = request.form.get("username", "")
                pw = request.form.get("password", "")
                if (hmac.compare_digest(user, state["admin"]["username"])
                        and st.verify_password(pw, state["admin"]["password_hash"])):
                    with _fail_lock:
                        _login_failures.pop(ip, None)
                    session.clear()
                    session.permanent = True
                    session["user"] = user
                    session["csrf"] = secrets.token_urlsafe(32)
                    nxt = request.args.get("next", "")
                    if not nxt.startswith("/") or nxt.startswith("//"):
                        nxt = url_for("dashboard")
                    return redirect(nxt)
                time.sleep(1)
                fails += 1
                with _fail_lock:
                    _login_failures[ip] = [fails, time.time() + 300 if fails >= 5 else 0.0]
                error = "Benutzername oder Passwort falsch."
        return render_template("login.html", error=error), (401 if error else 200)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/ca.crt")
    def ca_download():
        return Response(pki.ca_pem(), mimetype="application/x-x509-ca-cert",
                        headers={"Content-Disposition": "attachment; filename=vpn-server-ca.crt"})

    # ------------------------------------------------------------------
    # Einrichtungsassistent
    # ------------------------------------------------------------------

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        state = get_state()
        step = "password" if state["admin"].get("must_change") else "server"
        if request.method == "POST":
            if step == "password":
                pw1 = request.form.get("password", "")
                pw2 = request.form.get("password2", "")
                if len(pw1) < 10:
                    flash("Das Passwort muss mindestens 10 Zeichen lang sein.", "error")
                elif pw1 != pw2:
                    flash("Die Passwörter stimmen nicht überein.", "error")
                elif pw1 == state["admin"].get("initial_password"):
                    flash("Bitte ein neues Passwort wählen.", "error")
                else:
                    with st.locked():
                        s = st.load()
                        s["admin"]["password_hash"] = st.hash_password(pw1)
                        s["admin"]["must_change"] = False
                        s["admin"]["initial_password"] = ""
                        st.save(s)
                        system.write_issue(s)
                    if request.form.get("system_too"):
                        system.set_system_password("vpnadmin", pw1)
                    flash("Passwort gespeichert.", "ok")
                    return redirect(url_for("setup"))
            else:
                host = request.form.get("public_host", "").strip().lower()
                dns = [d.strip() for d in request.form.get("dns", "").replace(";", ",").split(",")
                       if d.strip()]
                errors = _validate_host_dns(host, dns)
                if errors:
                    for e in errors:
                        flash(e, "error")
                else:
                    def do(s):
                        s["server"]["public_host"] = host
                        s["server"]["dns"] = dns
                        s["server"]["setup_done"] = True
                    modify(do)
                    flash("Einrichtung abgeschlossen. Richten Sie jetzt die Portfreigaben am "
                          "Router ein und legen Sie den ersten Client an.", "ok")
                    return redirect(url_for("dashboard"))
        return render_template("setup.html", step=step, state=state,
                               lan_ip=util.default_route_info().get("ip", ""))

    def _validate_host_dns(host: str, dns: list[str]) -> list[str]:
        errors = []
        if not host or not util.valid_host(host):
            errors.append("Bitte eine gültige öffentliche Adresse (DNS-Name oder IP) angeben.")
        else:
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private:
                    errors.append("Die Adresse ist eine private (LAN-)IP. Clients aus dem Internet "
                                  "benötigen Ihre öffentliche IP oder einen DynDNS-Namen.")
            except ValueError:
                pass
        for d in dns:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                errors.append(f"Ungültiger DNS-Server: {d}")
        return errors

    @app.route("/api/detect-ip", methods=["POST"])
    def detect_ip():
        return jsonify(ip=system.detect_public_ip())

    # ------------------------------------------------------------------
    # Uebersicht
    # ------------------------------------------------------------------

    def port_forwards(state: dict) -> list[dict]:
        pr = state["proto"]
        rows = []
        if st.enabled(state, "wireguard"):
            rows.append(("WireGuard", "UDP", pr["wireguard"]["port"]))
        if st.enabled(state, "openvpn"):
            if pr["openvpn"]["udp"]:
                rows.append(("OpenVPN", "UDP", pr["openvpn"]["udp_port"]))
            if pr["openvpn"]["tcp"]:
                rows.append(("OpenVPN (TCP)", "TCP", pr["openvpn"]["tcp_port"]))
        if st.any_ipsec(state):
            rows.append(("IPsec: IKEv2, L2TP, Cisco IPsec", "UDP", 500))
            rows.append(("IPsec NAT-Traversal", "UDP", 4500))
        if st.enabled(state, "sstp"):
            rows.append(("SSTP", "TCP", pr["sstp"]["port"]))
        if st.enabled(state, "openconnect"):
            rows.append(("OpenConnect / AnyConnect", "TCP", pr["openconnect"]["port"]))
            rows.append(("OpenConnect (DTLS, schneller)", "UDP", pr["openconnect"]["port"]))
        if st.enabled(state, "pptp"):
            rows.append(("PPTP (+ GRE/PPTP-Passthrough am Router)", "TCP", 1723))
        if state["letsencrypt"].get("enabled"):
            rows.append(("Let's Encrypt (Zertifikatserneuerung)", "TCP", 80))
        if state["server"].get("webui_public"):
            rows.append(("Weboberfläche (nicht empfohlen)", "TCP", state["server"]["webui_port"]))
        return [{"label": l, "proto": p, "port": port} for l, p, port in rows]

    app.jinja_env.globals["port_forwards"] = port_forwards

    @app.route("/")
    def dashboard():
        state = get_state()
        units = status.unit_states(state)
        sessions = status.all_sessions(state)
        warnings = []
        host = state["server"].get("public_host", "")
        if host and util.is_ip(host) and state["ddns"].get("provider", "none") == "none":
            warnings.append("Die öffentliche Adresse ist eine IP-Adresse. Ändert Ihr Provider die "
                            "IP (Zwangstrennung), funktionieren die Profile nicht mehr. Empfohlen: "
                            "DynDNS-Namen verwenden (Einstellungen -> DynDNS oder im Router).")
        for u in units:
            if u["wanted"] and u["active"] not in ("active", "unbekannt"):
                warnings.append(f"Dienst '{u['label']}' läuft nicht ({u['active']}). Details unter Status.")
        if system.reboot_required():
            warnings.append("Nach Systemupdates ist ein Neustart erforderlich (System -> Neustart).")
        avail = state.get("update", {}).get("available") or {}
        if avail.get("newer") and not updater.running():
            warnings.append(f"Software-Update verfügbar: Version {avail.get('version')} "
                            f"({str(avail.get('sha', ''))[:7]}) – unter System → Software-Update installieren.")
        route = util.default_route_info()
        return render_template("dashboard.html", state=state, units=units, sessions=sessions,
                               warnings=warnings, lan_ip=route.get("ip", ""),
                               forwards=port_forwards(state), topo=_topology_info(state, route))

    def _topology_info(state: dict, route: dict) -> dict:
        nets = [{"key": "", "name": "Standardnetz",
                 "detail": "Heimnetz " + ("erlaubt" if state["server"].get("lan_access", True)
                                          else "gesperrt")}]
        for v in vlan.vlans(state):
            nets.append({"key": str(v["id"]), "name": f"VLAN {v['id']} · {v['name']}",
                         "detail": v["address"].split("/")[0] + (f" · Gateway {v['gateway']}"
                                                                if v.get("gateway") else "")})
        public_ip = (util.read_file(stats.PUBLIC_IP_FILE) or "").strip()
        return {"server": state["server"].get("name") or "VPN-Server",
                "host": state["server"].get("public_host", ""), "public_ip": public_ip,
                "lan_ip": route.get("ip", ""), "gateway": route.get("gateway", ""),
                "radius": bool(state["radius"].get("enabled")), "nets": nets}

    # ------------------------------------------------------------------
    # Statistik-APIs (lesen nur die Dateien von vpn-stats.service)
    # ------------------------------------------------------------------

    @app.route("/api/live")
    def api_live():
        state = get_state()
        data = stats.live()
        sessions = data.get("sessions") or []
        if data.get("stale") and not util.DRYRUN:
            sessions = status.all_sessions(state)
        for sess in sessions:
            v = vlan.vlan_of_ip(state, str(sess.get("vip", "")).split("/")[0])
            sess["net"] = str(v["id"]) if v else ""
        units = status.unit_states(state)
        bad = [u["label"] for u in units if u["wanted"] and u["active"] not in ("active", "unbekannt")]
        return jsonify(points=data["points"], cpu=data["cpu"], system=data["system"],
                       sessions=sessions, interval=data.get("interval", 2),
                       stale=bool(data.get("stale")), problems=bad,
                       today=stats.today_volume())

    @app.route("/api/history")
    def api_history():
        state = get_state()
        rng = request.args.get("range", "24h")
        data = stats.history(rng if rng in stats.RANGES else "24h")
        names = {str(v["id"]): f"VLAN {v['id']} · {v['name']}" for v in vlan.vlans(state)}
        data["vlan_names"] = names
        for c in data["clients"]:
            c["radius"] = c["name"] not in state["clients"]
        return jsonify(data)

    @app.route("/api/events")
    def api_events():
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        except ValueError:
            limit = 100
        return jsonify(events=stats.events(limit))

    # ------------------------------------------------------------------
    # Statistik und Werkzeuge
    # ------------------------------------------------------------------

    @app.route("/statistik")
    def statistics_page():
        state = get_state()
        return render_template("statistics.html", state=state, vlans=vlan.vlans(state))

    @app.route("/werkzeuge")
    def tools_page():
        state = get_state()
        return render_template("tools.html", state=state, interfaces=tools.capture_interfaces(),
                               wol=state.get("tools", {}).get("wol", []), dns_types=tools.DNS_TYPES)

    @app.route("/api/tools/<name>", methods=["POST"])
    def api_tool(name: str):
        form = request.form
        try:
            if name == "ping":
                return jsonify(ok=True, output=tools.ping(form.get("host", ""), form.get("count", 4)))
            if name == "traceroute":
                return jsonify(ok=True, output=tools.traceroute(form.get("host", "")))
            if name == "dns":
                return jsonify(ok=True, output=tools.dns(form.get("name", ""), form.get("type", "A"),
                                                         form.get("server", "")))
            if name == "speedtest":
                return jsonify(ok=True, result=tools.speedtest())
            if name == "wol":
                return jsonify(ok=True, output=tools.wake(form.get("mac", "")))
        except tools.ToolError as exc:
            return jsonify(ok=False, output=str(exc)), 400
        except OSError as exc:
            return jsonify(ok=False, output=f"Fehler: {exc}"), 502
        abort(404)

    @app.route("/werkzeuge/wol", methods=["POST"])
    def tools_wol_devices():
        action = request.form.get("action", "")
        try:
            def do(s):
                devices = s.setdefault("tools", {}).setdefault("wol", [])
                if action == "add":
                    name = request.form.get("name", "").strip()[:40] or "Gerät"
                    mac = tools.normalize_mac(request.form.get("mac", ""))
                    if any(d["mac"] == mac for d in devices):
                        raise tools.ToolError("Dieses Gerät ist bereits gespeichert.")
                    devices.append({"name": name, "mac": mac})
                elif action == "delete":
                    mac = request.form.get("mac", "")
                    s["tools"]["wol"] = [d for d in devices if d["mac"] != mac]
            with st.locked():
                s = st.load()
                do(s)
                st.save(s)
            flash("Gespeichert.", "ok")
        except tools.ToolError as exc:
            flash(str(exc), "error")
        return redirect(url_for("tools_page") + "#wol")

    @app.route("/werkzeuge/mitschnitt", methods=["POST"])
    def tools_capture():
        try:
            data = tools.capture(request.form.get("iface", "any"), request.form.get("seconds", 10),
                                 request.form.get("filter", ""))
        except (tools.ToolError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("tools_page") + "#capture")
        fname = f"mitschnitt-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
        return Response(data, mimetype="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    @app.route("/status/trennen", methods=["POST"])
    def status_disconnect():
        user = request.form.get("user", "").strip()
        if not user or len(user) > 128:
            abort(400)
        ap.disconnect_client(user)
        flash(f"Verbindungen von „{user}“ getrennt.", "ok")
        return redirect(url_for("status_page"))

    # ------------------------------------------------------------------
    # Clients
    # ------------------------------------------------------------------

    @app.route("/clients", methods=["GET", "POST"])
    def clients():
        if request.method == "POST":
            name = request.form.get("name", "").strip().lower()
            pw = request.form.get("password", "").strip()
            note = request.form.get("note", "").strip()[:100]
            full = request.form.get("tunnel", "full") == "full"
            vid = request.form.get("vlan", "").strip()
            try:
                modify(lambda s: st.new_client(s, name, password=pw or None, note=note,
                                               full_tunnel=full, vlan=vid))
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("clients"))
            flash(f"Client '{name}' angelegt.", "ok")
            return redirect(url_for("client", name=name))
        state = get_state()
        online = {s["user"] for s in status.all_sessions(state)}
        return render_template("clients.html", state=state, online=online,
                               vlans=vlan.vlans(state))

    def _get_client(state: dict, name: str) -> dict:
        client = state["clients"].get(name)
        if not client:
            abort(404)
        return client

    @app.route("/clients/<name>")
    def client(name: str):
        state = get_state()
        c = _get_client(state, name)
        share_url = None
        share = _active_share(state, name)
        if share:
            share_url = url_for("share", token=share, _external=True)
        return render_template("client.html", state=state, c=c, share_url=share_url,
                               share_qr=profiles.qr_svg(share_url) if share_url else None,
                               wg_qr=profiles.qr_svg(profiles.wireguard_conf(state, c))
                               if st.enabled(state, "wireguard") and c.get("enabled", True) else None,
                               dl=lambda kind: url_for("download", name=name, kind=kind),
                               info=_client_info(state), public=False, vlans=vlan.vlans(state),
                               client_vlan=vlan.client_vlan(state, c))

    def _client_info(state: dict) -> dict:
        return {
            "host": st.public_host(state),
            "ca_cn": pki.ca_common_name(),
            "pin": pki.server_pin_sha256(),
            "le": bool(state["letsencrypt"].get("enabled") and pki.le_available()),
            "psk": state["proto"]["ipsec_psk"],
            "sstp_addr": st.public_host(state) if int(state["proto"]["sstp"]["port"]) == 443
            else f"{st.public_host(state)}:{state['proto']['sstp']['port']}",
            "oc_addr": f"{st.public_host(state)}:{state['proto']['openconnect']['port']}",
        }

    @app.route("/clients/<name>/action", methods=["POST"])
    def client_action(name: str):
        action = request.form.get("action", "")
        state = get_state()
        _get_client(state, name)
        if action == "delete":
            def do(s):
                del s["clients"][name]
                s["shares"] = {k: v for k, v in s["shares"].items() if v["client"] != name}
                pki.revoke_client(name)
            modify(do)
            ap.disconnect_client(name)
            flash(f"Client '{name}' gelöscht, Zertifikat gesperrt und Verbindungen getrennt.", "ok")
            return redirect(url_for("clients"))
        if action == "toggle":
            def do(s):
                c = s["clients"][name]
                c["enabled"] = not c.get("enabled", True)
                if not c["enabled"]:
                    pki.revoke_client(name)
                return c["enabled"]
            now_enabled = modify(do)
            if not now_enabled:
                ap.disconnect_client(name)
                flash("Client gesperrt. Das Zertifikat wurde widerrufen.", "ok")
            else:
                flash("Client entsperrt. Zertifikatsbasierte Profile (OpenVPN, IKEv2-Zertifikat) "
                      "müssen neu installiert werden.", "ok")
        elif action == "reset-password":
            modify(lambda s: s["clients"][name].update(password=util.gen_password(16)))
            flash("Neues Passwort erzeugt.", "ok")
        elif action == "set-password":
            pw = request.form.get("password", "")
            if not util.valid_password(pw):
                flash("Ungültiges Passwort (8-64 Zeichen; erlaubt: A-Z a-z 0-9 - _ . : ! + = @ % ^ * ? , / ~).", "error")
            else:
                modify(lambda s: s["clients"][name].update(password=pw))
                flash("Passwort gespeichert.", "ok")
        elif action == "regen-psk":
            modify(lambda s: s["clients"][name].update(psk=util.gen_password(24)))
            flash("Neuer IKEv2-PSK erzeugt.", "ok")
        elif action == "regen-keys":
            def do(s):
                c = s["clients"][name]
                priv, pub = st.wg_keypair()
                c["wg"].update(privkey=priv, pubkey=pub, psk=st.wg_psk())
                c["p12_password"] = util.gen_password(12)
                pki.revoke_client(name)
            modify(do)
            ap.disconnect_client(name)
            flash("Neue Schlüssel und Zertifikate erzeugt. Alle Profile müssen neu installiert werden.", "ok")
        elif action == "update":
            note = request.form.get("note", "").strip()[:100]
            full = request.form.get("tunnel", "full") == "full"
            vid = request.form.get("vlan", None)

            def do(s):
                s["clients"][name].update(note=note, full_tunnel=full)
                if vid is not None:
                    return st.set_client_vlan(s, name, vid.strip())
                return False
            try:
                vlan_changed = modify(do)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("client", name=name))
            if vlan_changed:
                ap.disconnect_client(name)
                flash("Gespeichert. Das VLAN wurde geändert: bestehende Verbindungen wurden "
                      "getrennt, das WireGuard-Profil (neue Adresse) muss neu importiert werden.", "ok")
            else:
                flash("Gespeichert. WireGuard- und OpenVPN-Profile bitte neu importieren, falls die "
                      "Tunnel-Art geändert wurde.", "ok")
        elif action == "share":
            def do(s):
                token = util.gen_token(24)
                exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=SHARE_HOURS)).isoformat()
                s["shares"] = {k: v for k, v in s["shares"].items()
                               if v["client"] != name and not _expired(v)}
                s["shares"][token] = {"client": name, "expires": exp}
            with st.locked():
                s = st.load()
                do(s)
                st.save(s)
            flash(f"Teilen-Link erstellt (gültig {SHARE_HOURS} Stunden).", "ok")
        elif action == "unshare":
            with st.locked():
                s = st.load()
                s["shares"] = {k: v for k, v in s["shares"].items() if v["client"] != name}
                st.save(s)
            flash("Teilen-Link gelöscht.", "ok")
        else:
            abort(400)
        return redirect(url_for("client", name=name))

    @app.route("/clients/<name>/dl/<kind>")
    def download(name: str, kind: str):
        state = get_state()
        c = _get_client(state, name)
        return _download(state, c, kind)

    def _download(state: dict, c: dict, kind: str) -> Response:
        if not c.get("enabled", True):
            abort(404)
        try:
            fname, mime, data = profiles.generate(state, c, kind)
        except KeyError:
            abort(404)
        disp = "inline" if request.args.get("inline") and mime == "image/svg+xml" else "attachment"
        return Response(data, mimetype=mime,
                        headers={"Content-Disposition": f'{disp}; filename="{fname}"'})

    # ------------------------------------------------------------------
    # Teilen-Links (ohne Anmeldung, zeitlich begrenzt)
    # ------------------------------------------------------------------

    def _expired(share: dict) -> bool:
        try:
            return dt.datetime.fromisoformat(share["expires"]) < dt.datetime.now(dt.timezone.utc)
        except (KeyError, ValueError):
            return True

    def _active_share(state: dict, name: str) -> str | None:
        for token, share in state.get("shares", {}).items():
            if share["client"] == name and not _expired(share):
                return token
        return None

    def _share_client(token: str):
        state = get_state()
        if not state["server"].get("webui_public"):
            try:
                ip = ipaddress.ip_address(client_ip())
                if ip.version == 6 and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if not ip.is_private:
                    abort(404)
            except ValueError:
                abort(404)
        share = None
        for t, s in state.get("shares", {}).items():
            if hmac.compare_digest(t, token):
                share = s
        if not share or _expired(share):
            abort(404)
        c = state["clients"].get(share["client"])
        if not c or not c.get("enabled", True):
            abort(404)
        return state, c

    @app.route("/share/<token>")
    def share(token: str):
        state, c = _share_client(token)
        return render_template("share.html", state=state, c=c, public=True, share_url=None,
                               share_qr=None, wg_qr=None, info=_client_info(state),
                               dl=lambda kind: url_for("share_download", token=token, kind=kind))

    @app.route("/share/<token>/dl/<kind>")
    def share_download(token: str, kind: str):
        state, c = _share_client(token)
        return _download(state, c, kind)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @app.route("/status")
    def status_page():
        state = get_state()
        unit = request.args.get("log", "")
        units = status.unit_states(state)
        logtext = None
        if unit and unit in {u["unit"] for u in units} | {"vpn-webui.service"}:
            logtext = system.journal(unit)
        return render_template("status.html", state=state, units=units,
                               sessions=status.all_sessions(state), log_unit=unit, logtext=logtext)

    @app.route("/api/status")
    def api_status():
        state = get_state()
        return jsonify(units=status.unit_states(state), sessions=status.all_sessions(state))

    # ------------------------------------------------------------------
    # Einstellungen
    # ------------------------------------------------------------------

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            section = request.form.get("section", "")
            try:
                _save_settings(section, request.form)
            except ValueError as exc:
                flash(str(exc), "error")
            return redirect(url_for("settings") + "#" + section)
        state = get_state()
        edit = vlan.get(state, request.args.get("vlan", ""))
        route = util.default_route_info()
        return render_template("settings.html", state=state, providers=system.DDNS_PROVIDERS,
                               le_info=system.le_cert_info(), le_active=pki.le_available(),
                               cert=pki.server_cert_info(), ca_cn=pki.ca_common_name(),
                               vlans=[dict(v, link=vlan.link_state(v) if not util.DRYRUN else
                                           {"up": False, "text": "?"},
                                           members=len(vlan.vlan_clients(state, v)),
                                           ifname=vlan.ifname(v), parent_eff=vlan.parent_of(v))
                                      for v in vlan.vlans(state)],
                               vlan_edit=edit, interfaces=vlan.physical_interfaces(),
                               default_dev=route.get("dev", ""), lan_ip=route.get("ip", ""),
                               max_vlans=vlan.MAX_VLANS, radius_test=session.pop("radius_test", None))

    def _bool(form, key) -> bool:
        return form.get(key) in ("1", "on", "yes", "true")

    def _save_settings(section: str, form) -> None:
        if section == "general":
            host = form.get("public_host", "").strip().lower()
            dns = [d.strip() for d in form.get("dns", "").replace(";", ",").split(",") if d.strip()]
            errors = _validate_host_dns(host, dns)
            if errors:
                raise ValueError(" ".join(errors))
            name = form.get("name", "").strip()[:40] or "VPN-Server"

            def do(s):
                old = s["server"]["public_host"]
                s["server"].update(public_host=host, dns=dns, name=name,
                                   lan_access=_bool(form, "lan_access"),
                                   client_to_client=_bool(form, "client_to_client"),
                                   webui_public=_bool(form, "webui_public"),
                                   ssh_public=_bool(form, "ssh_public"))
                return old != host
            changed = modify(do)
            flash("Einstellungen gespeichert." + (
                " Die öffentliche Adresse wurde geändert - alle Client-Profile müssen neu "
                "verteilt werden." if changed else ""), "ok")
        elif section == "protocols":
            def do(s):
                pr = s["proto"]
                for p in PROTOCOLS:
                    pr[p]["enabled"] = _bool(form, f"{p}_enabled")
                ports = {
                    ("wireguard", "port"): form.get("wireguard_port"),
                    ("openvpn", "udp_port"): form.get("openvpn_udp_port"),
                    ("openvpn", "tcp_port"): form.get("openvpn_tcp_port"),
                    ("sstp", "port"): form.get("sstp_port"),
                    ("openconnect", "port"): form.get("openconnect_port"),
                }
                for (p, key), value in ports.items():
                    if value is None or value == "":
                        continue
                    if not util.valid_port(value):
                        raise ValueError(f"Ungültiger Port: {value}")
                    pr[p][key] = int(value)
                pr["openvpn"]["udp"] = _bool(form, "openvpn_udp")
                pr["openvpn"]["tcp"] = _bool(form, "openvpn_tcp")
                tcp_ports = []
                if pr["openvpn"]["enabled"] and pr["openvpn"]["tcp"]:
                    tcp_ports.append(pr["openvpn"]["tcp_port"])
                if pr["sstp"]["enabled"]:
                    tcp_ports.append(pr["sstp"]["port"])
                if pr["openconnect"]["enabled"]:
                    tcp_ports.append(pr["openconnect"]["port"])
                tcp_ports.append(s["server"]["webui_port"])
                tcp_ports += [22, 80, 1723]
                if len(tcp_ports) != len(set(tcp_ports)):
                    raise ValueError("TCP-Ports überschneiden sich (SSTP, OpenConnect, OpenVPN TCP, "
                                     "Weboberfläche, 22, 80, 1723 müssen verschieden sein).")
                udp_ports = [500, 4500, 1701]
                if pr["wireguard"]["enabled"]:
                    udp_ports.append(pr["wireguard"]["port"])
                if pr["openvpn"]["enabled"] and pr["openvpn"]["udp"]:
                    udp_ports.append(pr["openvpn"]["udp_port"])
                if pr["openconnect"]["enabled"]:
                    udp_ports.append(pr["openconnect"]["port"])
                if len(udp_ports) != len(set(udp_ports)):
                    raise ValueError("UDP-Ports überschneiden sich (500, 4500 und 1701 sind für "
                                     "IPsec reserviert).")
                mtu = form.get("wireguard_mtu", "").strip()
                pr["wireguard"]["mtu"] = int(mtu) if mtu.isdigit() and 1280 <= int(mtu) <= 1500 else 0
                subnets = {
                    ("wireguard", "subnet"): form.get("wireguard_subnet"),
                    ("openvpn", "udp_subnet"): form.get("openvpn_udp_subnet"),
                    ("openvpn", "tcp_subnet"): form.get("openvpn_tcp_subnet"),
                    ("ikev2", "subnet"): form.get("ikev2_subnet"),
                    ("ppp", "subnet"): form.get("ppp_subnet"),
                    ("openconnect", "subnet"): form.get("openconnect_subnet"),
                }
                wg_changed = False
                for (p, key), value in subnets.items():
                    value = (value or "").strip()
                    if not value or value == pr[p][key]:
                        continue
                    if not util.valid_ipv4_subnet(value):
                        raise ValueError(f"Ungültiges Subnetz: {value} (IPv4, /16 bis /28)")
                    pr[p][key] = value
                    wg_changed |= p == "wireguard"
                nets = [ipaddress.ip_network(n) for n in st.vpn_subnets(s)]
                for i, a in enumerate(nets):
                    for b in nets[i + 1:]:
                        if a.overlaps(b):
                            raise ValueError(f"Subnetze überschneiden sich: {a} / {b}")
                if wg_changed:
                    st.renumber_wireguard(s)
            modify(do)
            flash("Protokoll-Einstellungen gespeichert. Portfreigaben ggf. anpassen.", "ok")
        elif section == "ipsec":
            psk = form.get("ipsec_psk", "").strip()
            if form.get("regen"):
                psk = util.gen_password(24)
            if not util.valid_password(psk) or len(psk) < 12:
                raise ValueError("Der IPsec-PSK muss 12-64 Zeichen lang sein (A-Z a-z 0-9 - _ . : ! + = @ % ^ * ? , / ~).")
            modify(lambda s: s["proto"].update(ipsec_psk=psk))
            flash("IPsec-PSK gespeichert. L2TP- und Cisco-IPsec-Clients müssen angepasst werden.", "ok")
        elif section == "radius":
            _save_radius(form)
        elif section == "radius-test":
            ok, msg = system.radius_test(get_state(), form.get("test_user", "").strip(),
                                         form.get("test_password", ""),
                                         "mschap" if form.get("test_method") == "mschap" else "pap")
            session["radius_test"] = {"ok": ok, "msg": msg}
        elif section == "vlan-save":
            old_id = form.get("old_id", "").strip() or None

            def do(s):
                v = vlan.validate(s, form, old_id)
                if old_id and str(v["id"]) != str(old_id):
                    for c in s["clients"].values():
                        if str(c.get("vlan", "")) == str(old_id):
                            c["vlan"] = str(v["id"])
                    del s["vlans"][str(old_id)]
                old = s["vlans"].get(str(v["id"]))
                s["vlans"][str(v["id"])] = v
                if old and old["vpn_net"] != v["vpn_net"]:
                    st.renumber_vlan_clients(s, v["id"])
                return v
            v = modify(do)
            flash(f"VLAN {v['id']} ({v['name']}) gespeichert.", "ok")
        elif section == "vlan-delete":
            vid = form.get("id", "").strip()

            def do(s):
                if vid not in s["vlans"]:
                    raise ValueError("Unbekanntes VLAN.")
                moved = [c["name"] for c in s["clients"].values() if str(c.get("vlan", "")) == vid]
                for name in moved:
                    st.set_client_vlan(s, name, "")
                del s["vlans"][vid]
                return moved
            moved = modify(do)
            for name in moved:
                ap.disconnect_client(name)
            flash(f"VLAN {vid} gelöscht." + (
                f" {len(moved)} Client(s) sind jetzt im Standardnetz (WireGuard-Profile neu "
                "importieren)." if moved else ""), "ok")
        elif section == "ddns":
            provider = form.get("provider", "none")
            if provider not in system.DDNS_PROVIDERS:
                raise ValueError("Unbekannter Anbieter.")
            url = form.get("url", "").strip()
            if url and not url.startswith(("https://", "http://")):
                raise ValueError("Die URL muss mit https:// beginnen.")

            def do(s):
                s["ddns"].update(provider=provider, domain=form.get("domain", "").strip(),
                                 token=form.get("token", "").strip(), url=url,
                                 username=form.get("username", "").strip(),
                                 last_ip="")
                if form.get("password"):
                    s["ddns"]["password"] = form.get("password")
                result = system.ddns_update(s, force=True) if provider != "none" else ""
                if provider != "none" and _bool(form, "use_as_host") and s["ddns"]["domain"]:
                    domain = s["ddns"]["domain"]
                    if provider == "duckdns" and not domain.endswith(".duckdns.org"):
                        domain += ".duckdns.org"
                    s["server"]["public_host"] = domain
                return result
            result = modify(do)
            flash("DynDNS gespeichert. " + (result or ""), "ok")
        elif section == "ddns-update":
            with st.locked():
                s = st.load()
                result = system.ddns_update(s, force=True)
                st.save(s)
            flash(result, "ok")
        elif section == "letsencrypt":
            if form.get("disable"):
                modify(lambda s: s["letsencrypt"].update(enabled=False, status="deaktiviert"))
                flash("Let's Encrypt deaktiviert - es wird wieder das eigene Zertifikat verwendet.", "ok")
                return
            email = form.get("email", "").strip()

            def prepare(s):
                s["letsencrypt"]["email"] = email
                s["letsencrypt"]["enabled"] = True  # Port 80 oeffnen
            modify(prepare)
            ok, msg = system.letsencrypt_request(get_state())

            def finish(s):
                s["letsencrypt"]["enabled"] = ok
                s["letsencrypt"]["status"] = msg
            modify(finish)
            flash(msg, "ok" if ok else "error")
        else:
            abort(400)

    def _save_radius(form) -> None:
        servers = []
        for i in (1, 2):
            host = form.get(f"host{i}", "").strip()
            if not host:
                continue
            if not util.is_ip(host):
                # FreeRADIUS loest Namen nur beim Start auf; ein nicht aufloesbarer Name
                # wuerde auch die Anmeldung lokaler Benutzer verhindern
                raise ValueError(f"Bitte die IP-Adresse des RADIUS-Servers angeben (nicht „{host}“).")
            ports = []
            for key, default in ((f"auth_port{i}", 1812), (f"acct_port{i}", 1813)):
                value = form.get(key, "").strip() or str(default)
                if not util.valid_port(value):
                    raise ValueError(f"Ungültiger Port: {value}")
                ports.append(int(value))
            servers.append({"host": host, "auth_port": ports[0], "acct_port": ports[1],
                            "secret": form.get(f"secret{i}", ""), "index": i})
        nas_id = form.get("nas_identifier", "").strip() or "vpn-server"
        if not util.HOSTNAME_RE.match(nas_id) and not re.match(r"^[\w.-]{1,64}$", nas_id):
            raise ValueError("Ungültiger NAS-Identifier (Buchstaben, Ziffern, Punkt, Bindestrich).")

        def do(s):
            r = s["radius"]
            old = {i + 1: srv for i, srv in enumerate(r.get("servers", []))}
            out = []
            for srv in servers:
                secret = srv.pop("secret")
                idx = srv.pop("index")
                if not secret and old.get(idx, {}).get("host") == srv["host"]:
                    secret = old[idx]["secret"]  # unveraendert lassen
                if not secret:
                    raise ValueError(f"Bitte das gemeinsame Geheimnis für {srv['host']} eingeben.")
                if not re.match(r"^[\x20-\x7e]{1,128}$", secret) or any(ch in secret for ch in "'\"\\"):
                    raise ValueError("Das Geheimnis darf keine Anführungszeichen, keinen Backslash "
                                     "und keine Sonderzeichen außerhalb von ASCII enthalten.")
                out.append(dict(srv, secret=secret))
            enabled = _bool(form, "enabled")
            if enabled and not out:
                raise ValueError("Bitte mindestens einen RADIUS-Server eintragen.")
            local_users = _bool(form, "local_users")
            r.update(enabled=enabled, servers=out, nas_identifier=nas_id,
                     accounting=_bool(form, "accounting"), local_users=local_users,
                     unknown_vlan="default" if form.get("unknown_vlan") == "default" else "reject",
                     no_vlan="reject" if form.get("no_vlan") == "reject" else "default")
        modify(do)
        flash("RADIUS-Einstellungen gespeichert.", "ok")

    @app.route("/radius-profile")
    def radius_profiles():
        state = get_state()
        return render_template("radius_profiles.html", state=state, info=_client_info(state),
                               kinds=[k for k in profiles.RADIUS_DOWNLOADS
                                      if not profiles.DOWNLOADS[k][2]
                                      or st.enabled(state, profiles.DOWNLOADS[k][2])])

    @app.route("/radius-profile/dl/<kind>")
    def radius_download(kind: str):
        state = get_state()
        try:
            fname, mime, data = profiles.generate_generic(state, kind)
        except KeyError:
            abort(404)
        return Response(data, mimetype=mime,
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    @app.route("/system", methods=["GET", "POST"])
    def system_page():
        if request.method == "POST":
            action = request.form.get("action", "")
            state = get_state()
            if action == "password":
                if not st.verify_password(request.form.get("current", ""),
                                          state["admin"]["password_hash"]):
                    flash("Aktuelles Passwort ist falsch.", "error")
                elif len(request.form.get("password", "")) < 10:
                    flash("Das neue Passwort muss mindestens 10 Zeichen lang sein.", "error")
                elif request.form.get("password") != request.form.get("password2"):
                    flash("Die Passwörter stimmen nicht überein.", "error")
                else:
                    pw = request.form["password"]
                    with st.locked():
                        s = st.load()
                        s["admin"]["password_hash"] = st.hash_password(pw)
                        st.save(s)
                    if request.form.get("system_too"):
                        system.set_system_password("vpnadmin", pw)
                    flash("Passwort geändert.", "ok")
            elif action == "network":
                try:
                    method = request.form.get("method", "dhcp")
                    dns = [d.strip() for d in request.form.get("dns", "").split(",") if d.strip()]
                    new_ip = system.set_network(
                        request.form.get("dev", ""), method, request.form.get("address", "").strip(),
                        int(request.form.get("prefixlen", "24") or 24),
                        request.form.get("gateway", "").strip(), dns)
                    msg = "Netzwerk wird in wenigen Sekunden neu gestartet."
                    if new_ip:
                        msg += f" Neue Adresse: https://{new_ip}:{state['server']['webui_port']}"
                    flash(msg, "ok")
                except ValueError as exc:
                    flash(f"Fehler: {exc}", "error")
            elif action in ("reboot", "poweroff"):
                system.schedule(action)
                return render_template("message.html", title="Bitte warten",
                                       message="Der Server wird neu gestartet." if action == "reboot"
                                       else "Der Server wird heruntergefahren.")
            elif action == "update":
                system.start_update()
                flash("Update gestartet. Der Fortschritt erscheint unten im Protokoll.", "ok")
            elif action == "app-update-settings":
                repo = request.form.get("repo", "").strip()
                channel = request.form.get("channel", "release")
                branch = request.form.get("branch", "").strip()
                try:
                    updater.validate_settings(repo, channel, branch or "main")
                    with st.locked():
                        s = st.load()
                        u = updater.settings(s)
                        if repo != u["repo"]:
                            u["available"] = {}
                        u.update(repo=repo, channel=channel, branch=branch or u["branch"],
                                 auto=request.form.get("auto") == "1")
                        if request.form.get("token_clear"):
                            u["token"] = ""
                        elif request.form.get("token", "").strip():
                            tok = request.form["token"].strip()
                            if not re.match(r"^[A-Za-z0-9_]{20,255}$", tok):
                                raise updater.UpdateError("Das Token hat ein ungültiges Format.")
                            u["token"] = tok
                        st.save(s)
                    flash("Update-Einstellungen gespeichert.", "ok")
                except updater.UpdateError as exc:
                    flash(str(exc), "error")
            elif action == "app-update-check":
                try:
                    with st.locked():
                        s = st.load()
                        avail = updater.check(s)
                        st.save(s)
                    flash(f"Version {avail['version']} ({avail['sha'][:7]}) ist verfügbar." if avail["newer"]
                          else "Die installierte Version ist aktuell.", "ok")
                except updater.UpdateError as exc:
                    flash(str(exc), "error")
            elif action in ("app-update-install", "app-update-rollback"):
                try:
                    updater.start("install" if action == "app-update-install" else "rollback")
                    flash("Gestartet. Der Fortschritt erscheint unten; die Weboberfläche startet dabei "
                          "kurz neu.", "ok")
                except updater.UpdateError as exc:
                    flash(str(exc), "error")
                return redirect(url_for("system_page") + "#software")
            elif action == "restore":
                upload = request.files.get("backup")
                if not upload:
                    flash("Keine Datei ausgewählt.", "error")
                else:
                    try:
                        with st.locked():
                            system.restore_bytes(upload.read())
                            s = st.load()
                            ap.apply(s)
                            st.save(s)
                        flash("Sicherung wiederhergestellt.", "ok")
                    except ValueError as exc:
                        flash(f"Wiederherstellung fehlgeschlagen: {exc}", "error")
            else:
                abort(400)
            return redirect(url_for("system_page"))
        state = get_state()
        upd = updater.settings(state)
        return render_template("system.html", state=state, net=system.network_info(), upd=upd,
                               installed=updater.installed(), app_update=updater.status(),
                               uptime=system.uptime(), os_name=system.os_name(),
                               reboot=system.reboot_required(), hostname=util.hostname(),
                               update_running=system.update_running(),
                               update_log=(util.read_file(system.UPDATE_LOG) or "")[-6000:])

    @app.route("/api/update/status")
    def api_update_status():
        data = updater.status()
        data["installed"] = updater.installed()
        return jsonify(data)

    @app.route("/system/backup")
    def backup():
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        return Response(system.backup_bytes(), mimetype="application/gzip",
                        headers={"Content-Disposition":
                                 f'attachment; filename="vpn-server-backup-{stamp}.tar.gz"'})

    return app
