"""Weboberflaeche (Flask)."""

from __future__ import annotations

import datetime as dt
import hmac
import ipaddress
import secrets
import threading
import time

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)

from .. import __version__, apply as ap, pki, profiles, state as st, status, system, util
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
                abort(400, "Ungueltiges CSRF-Token - bitte Seite neu laden.")
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
                    flash("Die Passwoerter stimmen nicht ueberein.", "error")
                elif pw1 == state["admin"].get("initial_password"):
                    flash("Bitte ein neues Passwort waehlen.", "error")
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
            errors.append("Bitte eine gueltige oeffentliche Adresse (DNS-Name oder IP) angeben.")
        else:
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private:
                    errors.append("Die Adresse ist eine private (LAN-)IP. Clients aus dem Internet "
                                  "benoetigen Ihre oeffentliche IP oder einen DynDNS-Namen.")
            except ValueError:
                pass
        for d in dns:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                errors.append(f"Ungueltiger DNS-Server: {d}")
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
            rows.append(("Weboberflaeche (nicht empfohlen)", "TCP", state["server"]["webui_port"]))
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
            warnings.append("Die oeffentliche Adresse ist eine IP-Adresse. Aendert Ihr Provider die "
                            "IP (Zwangstrennung), funktionieren die Profile nicht mehr. Empfohlen: "
                            "DynDNS-Namen verwenden (Einstellungen -> DynDNS oder im Router).")
        for u in units:
            if u["wanted"] and u["active"] != "active":
                warnings.append(f"Dienst '{u['label']}' laeuft nicht ({u['active']}). Details unter Status.")
        if system.reboot_required():
            warnings.append("Nach Systemupdates ist ein Neustart erforderlich (System -> Neustart).")
        return render_template("dashboard.html", state=state, units=units, sessions=sessions,
                               warnings=warnings, lan_ip=util.default_route_info().get("ip", ""),
                               forwards=port_forwards(state))

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
            try:
                modify(lambda s: st.new_client(s, name, password=pw or None, note=note,
                                               full_tunnel=full))
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("clients"))
            flash(f"Client '{name}' angelegt.", "ok")
            return redirect(url_for("client", name=name))
        state = get_state()
        online = {s["user"] for s in status.all_sessions(state)}
        return render_template("clients.html", state=state, online=online)

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
                               info=_client_info(state), public=False)

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
            flash(f"Client '{name}' geloescht, Zertifikat gesperrt und Verbindungen getrennt.", "ok")
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
                      "muessen neu installiert werden.", "ok")
        elif action == "reset-password":
            modify(lambda s: s["clients"][name].update(password=util.gen_password(16)))
            flash("Neues Passwort erzeugt.", "ok")
        elif action == "set-password":
            pw = request.form.get("password", "")
            if not util.valid_password(pw):
                flash("Ungueltiges Passwort (8-64 Zeichen; erlaubt: A-Z a-z 0-9 - _ . : ! + = @ % ^ * ? , / ~).", "error")
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
            flash("Neue Schluessel und Zertifikate erzeugt. Alle Profile muessen neu installiert werden.", "ok")
        elif action == "update":
            note = request.form.get("note", "").strip()[:100]
            full = request.form.get("tunnel", "full") == "full"
            modify(lambda s: s["clients"][name].update(note=note, full_tunnel=full))
            flash("Gespeichert. WireGuard- und OpenVPN-Profile bitte neu importieren, falls die "
                  "Tunnel-Art geaendert wurde.", "ok")
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
            flash(f"Teilen-Link erstellt (gueltig {SHARE_HOURS} Stunden).", "ok")
        elif action == "unshare":
            with st.locked():
                s = st.load()
                s["shares"] = {k: v for k, v in s["shares"].items() if v["client"] != name}
                st.save(s)
            flash("Teilen-Link geloescht.", "ok")
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
        return render_template("settings.html", state=state, providers=system.DDNS_PROVIDERS,
                               le_info=system.le_cert_info(), le_active=pki.le_available(),
                               cert=pki.server_cert_info(), ca_cn=pki.ca_common_name())

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
                " Die oeffentliche Adresse wurde geaendert - alle Client-Profile muessen neu "
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
                        raise ValueError(f"Ungueltiger Port: {value}")
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
                    raise ValueError("TCP-Ports ueberschneiden sich (SSTP, OpenConnect, OpenVPN TCP, "
                                     "Weboberflaeche, 22, 80, 1723 muessen verschieden sein).")
                udp_ports = [500, 4500, 1701]
                if pr["wireguard"]["enabled"]:
                    udp_ports.append(pr["wireguard"]["port"])
                if pr["openvpn"]["enabled"] and pr["openvpn"]["udp"]:
                    udp_ports.append(pr["openvpn"]["udp_port"])
                if pr["openconnect"]["enabled"]:
                    udp_ports.append(pr["openconnect"]["port"])
                if len(udp_ports) != len(set(udp_ports)):
                    raise ValueError("UDP-Ports ueberschneiden sich (500, 4500 und 1701 sind fuer "
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
                        raise ValueError(f"Ungueltiges Subnetz: {value} (IPv4, /16 bis /28)")
                    pr[p][key] = value
                    wg_changed |= p == "wireguard"
                nets = [ipaddress.ip_network(n) for n in st.vpn_subnets(s)]
                for i, a in enumerate(nets):
                    for b in nets[i + 1:]:
                        if a.overlaps(b):
                            raise ValueError(f"Subnetze ueberschneiden sich: {a} / {b}")
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
            flash("IPsec-PSK gespeichert. L2TP- und Cisco-IPsec-Clients muessen angepasst werden.", "ok")
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
                    flash("Die Passwoerter stimmen nicht ueberein.", "error")
                else:
                    pw = request.form["password"]
                    with st.locked():
                        s = st.load()
                        s["admin"]["password_hash"] = st.hash_password(pw)
                        st.save(s)
                    if request.form.get("system_too"):
                        system.set_system_password("vpnadmin", pw)
                    flash("Passwort geaendert.", "ok")
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
            elif action == "restore":
                upload = request.files.get("backup")
                if not upload:
                    flash("Keine Datei ausgewaehlt.", "error")
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
        return render_template("system.html", state=state, net=system.network_info(),
                               uptime=system.uptime(), os_name=system.os_name(),
                               reboot=system.reboot_required(), hostname=util.hostname(),
                               update_running=system.update_running(),
                               update_log=(util.read_file(system.UPDATE_LOG) or "")[-6000:])

    @app.route("/system/backup")
    def backup():
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        return Response(system.backup_bytes(), mimetype="application/gzip",
                        headers={"Content-Disposition":
                                 f'attachment; filename="vpn-server-backup-{stamp}.tar.gz"'})

    return app
