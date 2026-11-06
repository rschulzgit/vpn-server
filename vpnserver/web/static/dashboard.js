// VPN-Server: Uebersicht mit Live-Durchsatz, System, Netzwerkplan und Verlauf
(function () {
  "use strict";
  var C = window.VPNCharts, h = C.h;
  var topo = JSON.parse(document.getElementById("dash-data").textContent || "{}");
  window.VPN_LIVE_PAGE = true;   // app.js fragt dann nicht zusaetzlich ab

  var PROTOS = [
    ["WireGuard", /^wireguard/i], ["OpenVPN", /^openvpn/i], ["IKEv2", /^ikev2/i], ["L2TP", /^l2tp/i],
    ["Cisco IPsec", /cisco|xauth/i], ["SSTP", /^sstp/i], ["OpenConnect", /^openconnect/i], ["PPTP", /^pptp/i]
  ];
  function protoSlot(label) {
    for (var i = 0; i < PROTOS.length; i++) if (PROTOS[i][1].test(label || "")) return i + 1;
    return 1;
  }
  function $(id) { return document.getElementById(id); }

  var live = new C.LineChart($("live-chart"), {
    label: "Durchsatz der VPN-Clients, letzte 5 Minuten", height: 230,
    series: [{ key: "down", label: "Download" }, { key: "up", label: "Upload" }],
    empty: "Warte auf Messwerte …"
  });

  function meter(id, pct, text) {
    var m = $(id);
    pct = Math.max(0, Math.min(100, pct || 0));
    m.firstElementChild.style.width = pct + "%";
    m.classList.toggle("warn", pct >= 75 && pct < 90);
    m.classList.toggle("crit", pct >= 90);
    $(id + "-v").textContent = text;
  }

  function renderTopology(sessions) {
    var box = $("topo-nets");
    C.clear(box);
    (topo.nets || []).forEach(function (net) {
      var mine = sessions.filter(function (s) { return (s.net || "") === net.key; });
      var card = h("div", "topo-net", null, box);
      var head = h("div", "topo-net-head", null, card);
      h("span", null, net.name, head);
      if (net.detail) h("small", null, net.detail, head);
      h("span", "badge " + (mine.length ? "ok" : ""), mine.length + (mine.length === 1 ? " Gerät" : " Geräte"), head);
      if (!mine.length) { h("div", "topo-empty", "Keine Geräte verbunden", card); return; }
      var list = h("div", "topo-devices", null, card);
      mine.slice(0, 24).forEach(function (s) {
        var known = (topo.clients || []).indexOf(s.user) >= 0;
        var d = h("a", "topo-dev", null, list);
        d.href = known ? topo.client_url.replace("__NAME__", encodeURIComponent(s.user)) : topo.sessions_url;
        h("i", "dot bg-p" + protoSlot(s.proto), null, d);
        h("span", null, s.user || "?", d);
        h("small", null, (s.proto || "") + " · " + (s.vip || ""), d);
        d.title = (s.user || "") + " – " + (s.proto || "") + ", " + (s.vip || "") + (s.remote ? ", von " + s.remote : "") +
          (known ? " · Client öffnen" : " · Verbindungen anzeigen");
      });
      if (mine.length > 24) h("span", "topo-dev", "+" + (mine.length - 24) + " weitere", list);
    });
  }

  function renderProtocols(sessions) {
    var counts = PROTOS.map(function () { return 0; });
    sessions.forEach(function (s) { counts[protoSlot(s.proto) - 1]++; });
    C.segBar($("proto-bar"), $("proto-legend"), PROTOS.map(function (p, i) {
      return { name: p[0] + " (" + counts[i] + ")", value: counts[i], slot: i + 1 };
    }));
  }

  function updateLive(d) {
    $("stale-box").classList.toggle("hidden", !d.stale);
    var pts = d.points || [];
    live.update(pts);
    var last = pts.length ? pts[pts.length - 1] : [0, 0, 0];
    $("t-down").textContent = C.fmtRate(last[1]);
    $("t-up").textContent = C.fmtRate(last[2]);
    $("lg-down").textContent = C.fmtRate(last[1]);
    $("lg-up").textContent = C.fmtRate(last[2]);
    var recent = pts.slice(-45);
    C.sparkline($("sp-down"), recent.map(function (p) { return p[1]; }), "sp-dot-down");
    C.sparkline($("sp-up"), recent.map(function (p) { return p[2]; }), "sp-dot-up");
    var sessions = d.sessions || [];
    $("t-conn").textContent = sessions.length;
    var radius = sessions.filter(function (s) { return s.radius; }).length;
    $("t-conn-sub").textContent = sessions.length
      ? (sessions.length - radius) + " Clients" + (radius ? " · " + radius + " RADIUS" : "")
      : "keine aktiven Verbindungen";
    var today = d.today || {};
    $("t-today").textContent = C.fmtBytes((today.down || 0) + (today.up || 0));
    $("t-today-sub").textContent = "↓ " + C.fmtBytes(today.down) + " · ↑ " + C.fmtBytes(today.up);
    var sys = d.system || {};
    var cpu = (d.cpu || []).length ? d.cpu[d.cpu.length - 1] : 0;
    meter("m-cpu", cpu, Math.round(cpu) + " %");
    if (sys.mem_total) meter("m-mem", sys.mem_used / sys.mem_total * 100, C.fmtBytes(sys.mem_used) + " / " + C.fmtBytes(sys.mem_total));
    if (sys.disk_total) meter("m-disk", sys.disk_used / sys.disk_total * 100, C.fmtBytes(sys.disk_used) + " / " + C.fmtBytes(sys.disk_total));
    C.sparkline($("sp-cpu"), (d.cpu || []).slice(-60), "sp-dot");
    $("f-load").textContent = sys.load ? sys.load.map(function (v) { return v.toFixed(2).replace(".", ","); }).join(" / ") : "–";
    $("f-temp").textContent = sys.temp ? String(sys.temp).replace(".", ",") + " °C" : "–";
    $("f-cpus").textContent = sys.cpus || "–";
    $("sys-uptime").textContent = sys.uptime ? "läuft seit " + C.fmtDuration(sys.uptime) : "";
    renderTopology(sessions);
    renderProtocols(sessions);
    if (window.VPNTopbar) window.VPNTopbar(d);
  }

  function poll() {
    if (document.hidden) return;
    fetch("/api/live", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) updateLive(d); })
      .catch(function () { /* naechster Versuch */ });
  }

  // ---------------------------------------------------------------- Verlauf
  var hist = new C.ColumnChart($("hist-chart"), { label: "Datenvolumen", height: 250 });
  var range = "24h", histData = null;
  function histTable() {
    var box = $("hist-table");
    C.clear(box);
    if (!histData) return;
    var t = h("table", null, null, box);
    var hr = h("tr", null, null, h("thead", null, null, t));
    h("th", null, histData.unit === "hour" ? "Stunde" : "Tag", hr);
    h("th", "num", "Download", hr); h("th", "num", "Upload", hr); h("th", "num", "Gesamt", hr);
    var tb = h("tbody", null, null, t);
    histData.series.slice().reverse().forEach(function (s) {
      var tr = h("tr", null, null, tb);
      h("td", null, s.label, tr);
      h("td", "num", C.fmtBytes(s.down), tr); h("td", "num", C.fmtBytes(s.up), tr);
      h("td", "num", C.fmtBytes(s.down + s.up), tr);
    });
  }
  function loadHistory() {
    $("hist-chart").classList.add("loading");
    fetch("/api/history?range=" + range, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        $("hist-chart").classList.remove("loading");
        if (!d) return;
        histData = d;
        hist.update(d.series);
        $("hist-total").textContent = "↓ " + C.fmtBytes(d.total.down) + " · ↑ " + C.fmtBytes(d.total.up);
        C.barList($("top-clients"), d.clients.map(function (c) {
          return { name: c.name, down: c.down, up: c.up, note: c.radius ? "RADIUS" : "" };
        }), { limit: 7, empty: "Noch kein Datenverkehr" });
        var vv = $("vlan-volume");
        if (vv) {
          var rows = Object.keys(d.vlans).map(function (k) {
            return { name: d.vlan_names[k] || ("VLAN " + k), down: d.vlans[k].down, up: d.vlans[k].up };
          }).sort(function (a, b) { return (b.down + b.up) - (a.down + a.up); });
          C.barList(vv, rows, { empty: "Noch kein Datenverkehr in den VLANs" });
        }
        if (!$("hist-table").classList.contains("hidden")) histTable();
      })
      .catch(function () { $("hist-chart").classList.remove("loading"); });
  }
  document.querySelectorAll("#range button").forEach(function (b) {
    b.addEventListener("click", function () {
      range = b.getAttribute("data-range");
      document.querySelectorAll("#range button").forEach(function (x) { x.classList.toggle("active", x === b); });
      loadHistory();
    });
  });
  $("hist-table-btn").addEventListener("click", function () {
    var box = $("hist-table");
    box.classList.toggle("hidden");
    this.textContent = box.classList.contains("hidden") ? "Als Tabelle" : "Tabelle ausblenden";
    if (!box.classList.contains("hidden")) histTable();
  });

  renderTopology([]);
  poll();
  loadHistory();
  setInterval(poll, 2000);
  setInterval(loadHistory, 60000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });
})();
