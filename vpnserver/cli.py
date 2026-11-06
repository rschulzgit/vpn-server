"""vpnctl - Kommandozeilenwerkzeug fuer den VPN-Server."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import pwd
import sys

from . import __version__, apply as ap, pki, profiles, state as st, status, system, util


def _load() -> dict:
    if not st.exists():
        sys.exit("Noch nicht initialisiert. Bitte zuerst 'vpnctl init' ausfuehren.")
    return st.load()


def _default_dns() -> list[str]:
    ns = util.system_nameservers()
    private = [n for n in ns if ipaddress.ip_address(n).is_private]
    return private[:2] if private else ["1.1.1.1", "9.9.9.9"]


def cmd_init(args) -> None:
    with st.locked():
        if st.exists() and not args.force:
            print("Bereits initialisiert - wende Konfiguration erneut an.")
            state = st.load()
        else:
            state = st.default_state()
            initial = args.password or util.gen_password(10)
            state["admin"]["initial_password"] = initial
            state["admin"]["password_hash"] = st.hash_password(initial)
            state["admin"]["must_change"] = True
            state["server"]["dns"] = _default_dns()
            if args.public_host:
                state["server"]["public_host"] = args.public_host
            st.ensure_server_keys(state)
            try:
                pwd.getpwnam("vpnadmin")
                system.set_system_password("vpnadmin", initial)
            except KeyError:
                pass
            st.save(state)
        ap.apply(state, restart_webui=False)
        st.save(state)
        system.write_issue(state)
    print("VPN-Server initialisiert.")
    if state["admin"].get("must_change"):
        print(f"  Weboberflaeche: https://{util.default_route_info().get('ip') or '<IP>'}:"
              f"{state['server']['webui_port']}")
        print(f"  Benutzer: {state['admin']['username']}   Initialpasswort: "
              f"{state['admin']['initial_password']}")


def cmd_apply(args) -> None:
    with st.locked():
        state = _load()
        msgs = ap.apply(state, restart_webui=not args.no_webui_restart)
        st.save(state)
    if not args.quiet:
        print("\n".join(msgs) or "Keine Aenderungen.")


def cmd_client(args) -> None:
    if args.action == "list":
        state = _load()
        for c in state["clients"].values():
            print(f"{c['name']:<32} {'aktiv' if c.get('enabled', True) else 'gesperrt':<9} "
                  f"WG {c['wg']['ip']:<15} {c.get('note', '')}")
        return
    if not args.name:
        sys.exit("Name fehlt.")
    if args.action == "add":
        with st.locked():
            state = _load()
            client = st.new_client(state, args.name, password=args.password,
                                   full_tunnel=not args.split)
            ap.apply(state)
            st.save(state)
        print(profiles.credentials_text(state, client))
    elif args.action in ("del", "delete", "remove"):
        with st.locked():
            state = _load()
            if args.name not in state["clients"]:
                sys.exit("Unbekannter Client.")
            del state["clients"][args.name]
            pki.revoke_client(args.name)
            ap.apply(state)
            st.save(state)
        ap.disconnect_client(args.name)
        print(f"Client {args.name} geloescht und Zertifikat gesperrt.")
    elif args.action == "show":
        state = _load()
        client = state["clients"].get(args.name) or sys.exit("Unbekannter Client.")
        print(profiles.credentials_text(state, client))
    elif args.action == "export":
        state = _load()
        client = state["clients"].get(args.name) or sys.exit("Unbekannter Client.")
        fname, _mime, data = profiles.generate(state, client, args.kind)
        out = args.output or fname
        if out == "-":
            sys.stdout.buffer.write(data)
        else:
            with open(out, "wb") as fh:
                fh.write(data)
            print(f"Geschrieben: {out}")


def cmd_set(args) -> None:
    with st.locked():
        state = _load()
        if args.key == "public-host":
            if not util.valid_host(args.value):
                sys.exit("Ungueltiger Hostname/IP.")
            state["server"]["public_host"] = args.value
        elif args.key == "dns":
            servers = [d.strip() for d in args.value.split(",") if d.strip()]
            for d in servers:
                ipaddress.ip_address(d)
            state["server"]["dns"] = servers
        elif args.key == "webui-public":
            state["server"]["webui_public"] = args.value.lower() in ("1", "yes", "ja", "true", "on")
        elif args.key in st.PROTOCOLS:
            state["proto"][args.key]["enabled"] = args.value.lower() in ("1", "yes", "ja", "true", "on")
        else:
            sys.exit("Unbekannter Schluessel.")
        ap.apply(state)
        st.save(state)
    print("OK")


def cmd_admin_password(args) -> None:
    with st.locked():
        state = _load()
        pw = args.password or util.gen_password(10)
        state["admin"]["password_hash"] = st.hash_password(pw)
        state["admin"]["initial_password"] = pw
        state["admin"]["must_change"] = True
        st.save(state)
        system.write_issue(state)
    print(f"Neues Passwort fuer '{state['admin']['username']}': {pw}")
    print("Es muss bei der naechsten Anmeldung geaendert werden.")


def cmd_status(_args) -> None:
    state = _load()
    print(f"VPN-Server {__version__} - oeffentliche Adresse: {st.public_host(state)}\n")
    for u in status.unit_states(state):
        mark = "OK " if u["ok"] else "!! "
        print(f"{mark}{u['label']:<42} {u['active']:<10} {'(aktiviert)' if u['wanted'] else '(aus)'}")
    sessions = status.all_sessions(state)
    print(f"\nVerbundene Clients: {len(sessions)}")
    for s in sessions:
        print(f"  {s['proto']:<22} {s['user']:<20} {s['vip']:<15} {s['remote']}")


def cmd_maintenance(_args) -> None:
    with st.locked():
        state = _load()
        pki.write_crl()
        ap.apply(state)
        system.ddns_update(state)
        st.save(state)
        system.write_issue(state)
    # Selbst-Update: taeglich pruefen, bei "automatisch" auch installieren
    from . import updater
    with st.locked():
        state = _load()
        msg = updater.maybe_auto_update(state)
        st.save(state)
    print(msg)


def cmd_ddns(args) -> None:
    with st.locked():
        state = _load()
        result = system.ddns_update(state, force=args.force)
        st.save(state)
    if not args.quiet:
        print(result)


def cmd_update(args) -> None:
    from . import updater
    if args.action == "run":
        sys.exit(updater.run_install())
    if args.action == "run-rollback":
        sys.exit(updater.run_rollback())
    if args.action == "status":
        stat = updater.status()
        inst = updater.installed()
        print(f"Installiert: {inst['version']} ({inst.get('sha', '')[:7] or '?'}, {inst.get('ref') or '?'})")
        print(f"Status:      {stat['state']} {stat.get('message', '')}")
        return
    with st.locked():
        state = _load()
        u = updater.settings(state)
        if args.action == "source":
            repo = args.repo or u["repo"]
            channel = args.channel or u["channel"]
            branch = args.branch or u["branch"]
            api = args.api or u["api"]
            try:
                updater.validate_settings(repo, channel, branch, api)
            except updater.UpdateError as exc:
                sys.exit(str(exc))
            u.update(repo=repo, channel=channel, branch=branch, api=api)
            if args.token is not None:
                u["token"] = args.token
            if args.auto is not None:
                u["auto"] = args.auto == "on"
            st.save(state)
            print(f"Quelle: {repo} ({'Releases' if channel == 'release' else 'Branch ' + branch}), "
                  f"automatisch: {'ja' if u['auto'] else 'nein'}")
            return
        try:
            avail = updater.check(state)
        except updater.UpdateError as exc:
            sys.exit(f"Fehler: {exc}")
        st.save(state)
    inst = updater.installed()
    print(f"Installiert: {inst['version']} ({inst.get('sha', '')[:7] or '?'})")
    print(f"Verfuegbar:  {avail['version']} ({avail['sha'][:7]}, {avail['ref']})"
          f"{' - Update verfuegbar' if avail['newer'] else ' - aktuell'}")
    if args.action == "install":
        if not avail["newer"] and not args.force:
            print("Bereits aktuell.")
            return
        updater.start("install")
        print(f"Update gestartet - Fortschritt: journalctl -fu {updater.UNIT} bzw. {updater.LOG_FILE}")
    elif args.action == "rollback":
        updater.start("rollback")
        print("Wiederherstellung gestartet.")


def cmd_stats_daemon(_args) -> None:
    from . import stats
    stats.run_daemon()


def cmd_vlan_dhcp_hook(args) -> None:
    """Von udhcpc aufgerufen (vpn-vlan-dhcp@.service): Adresse eines VLANs uebernehmen."""
    import time
    from . import vlan
    name = os.environ.get("interface", "")
    state = st.load()
    # Die Weboberflaeche speichert den Zustand erst nach dem Anwenden: kommt die Adresse
    # schneller, kurz warten, bis das VLAN (mit DHCP) gespeichert ist
    for _ in range(30):
        v = next((x for x in vlan.vlans(state) if vlan.ifname(x) == name), None)
        if args.event not in ("bound", "renew") or (v and vlan.is_dhcp(v)):
            break
        time.sleep(1)
        state = st.load()
    print(vlan.dhcp_event(state, args.event, dict(os.environ)), flush=True)


def cmd_issue(_args) -> None:
    system.write_issue(_load())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vpnctl", description="VPN-Server verwalten")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="Ersteinrichtung (Schluessel, Zertifikate, Dienste)")
    p.add_argument("--public-host")
    p.add_argument("--password", help="Initialpasswort vorgeben")
    p.add_argument("--force", action="store_true", help="Zustand komplett neu erzeugen")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("apply", help="Konfiguration schreiben und Dienste abgleichen")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--no-webui-restart", action="store_true")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("client", help="Clients verwalten")
    p.add_argument("action", choices=["list", "add", "del", "delete", "remove", "show", "export"])
    p.add_argument("name", nargs="?")
    p.add_argument("kind", nargs="?", default="zip", help="Export-Typ, z. B. wireguard, openvpn, zip")
    p.add_argument("--password")
    p.add_argument("--split", action="store_true", help="Nur VPN/Heimnetz ueber den Tunnel")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_client)

    p = sub.add_parser("set", help="Einstellung setzen (public-host, dns, webui-public, <protokoll>)")
    p.add_argument("key")
    p.add_argument("value")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("admin-password", help="Admin-Passwort zuruecksetzen")
    p.add_argument("password", nargs="?")
    p.set_defaults(func=cmd_admin_password)

    sub.add_parser("status", help="Dienste und Verbindungen anzeigen").set_defaults(func=cmd_status)
    sub.add_parser("maintenance", help="Taegliche Wartung").set_defaults(func=cmd_maintenance)
    sub.add_parser("issue", help="Konsolen-Banner neu schreiben").set_defaults(func=cmd_issue)
    sub.add_parser("stats-daemon", help="Verkehrsstatistik erfassen (vpn-stats.service)").set_defaults(
        func=cmd_stats_daemon)
    p = sub.add_parser("vlan-dhcp-hook", help=argparse.SUPPRESS)
    p.add_argument("event")
    p.set_defaults(func=cmd_vlan_dhcp_hook)

    p = sub.add_parser("update", help="Selbst-Update aus dem Repository (check, install, rollback, status, source)")
    p.add_argument("action", choices=["check", "install", "rollback", "status", "source", "run", "run-rollback"])
    p.add_argument("--repo")
    p.add_argument("--channel", choices=["release", "branch"])
    p.add_argument("--branch")
    p.add_argument("--api")
    p.add_argument("--token")
    p.add_argument("--auto", choices=["on", "off"])
    p.add_argument("--force", action="store_true", help="auch ohne neueren Stand installieren")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("ddns", help="DynDNS aktualisieren")
    p.add_argument("--force", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_ddns)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")
    if os.geteuid() != 0 and not util.ROOT:
        sys.exit("vpnctl muss als root laufen (sudo vpnctl ...).")
    try:
        args.func(args)
    except ValueError as exc:
        sys.exit(f"Fehler: {exc}")


if __name__ == "__main__":
    main()
