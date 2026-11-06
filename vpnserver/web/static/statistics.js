// VPN-Server: Statistikseite (Verlauf, je Benutzer, je Netz)
(function () {
  "use strict";
  var C = window.VPNCharts, h = C.h;
  var chart = new C.ColumnChart(document.getElementById("hist-chart"), { label: "Datenvolumen", height: 280 });
  var range = "24h";
  function $(id) { return document.getElementById(id); }

  function render(d) {
    chart.update(d.series);
    $("k-down").textContent = C.fmtBytes(d.total.down);
    $("k-up").textContent = C.fmtBytes(d.total.up);
    $("k-users").textContent = d.clients.length;
    var peak = null;
    d.series.forEach(function (s) { if (!peak || s.down + s.up > peak.down + peak.up) peak = s; });
    $("k-peak").textContent = peak && (peak.down + peak.up) ? C.fmtBytes(peak.down + peak.up) : "–";
    $("k-peak-sub").textContent = peak && (peak.down + peak.up) ? (d.unit === "hour" ? "um " : "am ") + peak.label : " ";
    $("sum").textContent = "Gesamt " + C.fmtBytes(d.total.down + d.total.up);
    var tb = document.querySelector("#clients tbody");
    C.clear(tb);
    var total = d.clients.reduce(function (a, c) { return a + c.down + c.up; }, 0);
    if (!d.clients.length) {
      var td = h("td", "muted", "Noch kein Datenverkehr in diesem Zeitraum.", h("tr", null, null, tb));
      td.colSpan = 5;
    }
    d.clients.forEach(function (c) {
      var tr = h("tr", null, null, tb);
      var name = h("td", null, c.name, tr);
      if (c.radius) { name.appendChild(document.createTextNode(" ")); h("span", "badge", "RADIUS", name); }
      h("td", "num", C.fmtBytes(c.down), tr);
      h("td", "num", C.fmtBytes(c.up), tr);
      h("td", "num", C.fmtBytes(c.down + c.up), tr);
      h("td", "num", total ? Math.round((c.down + c.up) / total * 100) + " %" : "–", tr);
    });
    var rows = [{ name: "Standardnetz", down: d.total.down, up: d.total.up }];
    Object.keys(d.vlans).forEach(function (k) {
      rows[0].down -= d.vlans[k].down;
      rows[0].up -= d.vlans[k].up;
      rows.push({ name: d.vlan_names[k] || ("VLAN " + k), down: d.vlans[k].down, up: d.vlans[k].up });
    });
    rows[0].down = Math.max(0, rows[0].down);
    rows[0].up = Math.max(0, rows[0].up);
    C.barList($("nets"), rows.filter(function (r) { return r.down + r.up > 0; }), { empty: "Noch kein Datenverkehr" });
  }
  function load() {
    $("hist-chart").classList.add("loading");
    fetch("/api/history?range=" + range, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { $("hist-chart").classList.remove("loading"); if (d) render(d); })
      .catch(function () { $("hist-chart").classList.remove("loading"); });
  }
  document.querySelectorAll("#range button").forEach(function (b) {
    b.addEventListener("click", function () {
      range = b.getAttribute("data-range");
      document.querySelectorAll("#range button").forEach(function (x) { x.classList.toggle("active", x === b); });
      load();
    });
  });
  load();
  setInterval(load, 60000);
})();
