// VPN-Server: Verbindungen live, Trennen, Verbindungsprotokoll
(function () {
  "use strict";
  var C = window.VPNCharts, h = C.h;
  var table = document.getElementById("live-sessions");
  var withVlans = !!table.getAttribute("data-vlans");
  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  function sessions(d) {
    var tb = table.querySelector("tbody");
    C.clear(tb);
    var list = d.sessions || [];
    document.getElementById("session-count").textContent = list.length;
    if (!list.length) {
      var td = h("td", "muted", "Keine Verbindungen.", h("tr", null, null, tb));
      td.colSpan = 9;
      return;
    }
    list.forEach(function (s) {
      var tr = h("tr", null, null, tb);
      var user = h("td", null, s.user || "", tr);
      if (s.radius) { user.appendChild(document.createTextNode(" ")); h("span", "badge", "RADIUS", user); }
      h("td", null, s.proto || "", tr);
      h("code", null, s.vip || "", h("td", null, null, tr));
      if (withVlans) h("td", null, s.vlan || "Standard", tr);
      h("td", null, s.remote || "", tr);
      h("td", "num", s.tx || "", tr);
      h("td", "num", s.rx || "", tr);
      h("td", null, s.since || "", tr);
      var cell = h("td", null, null, tr);
      var form = h("form", "inline-form", null, cell);
      form.method = "post";
      form.action = "/status/trennen";
      form.setAttribute("data-confirm", "Alle Verbindungen von " + (s.user || "") + " trennen?");
      [["csrf_token", csrf], ["user", s.user || ""]].forEach(function (f) {
        var i = h("input", null, null, form); i.type = "hidden"; i.name = f[0]; i.value = f[1];
      });
      var b = h("button", "btn small secondary", "Trennen", form); b.type = "submit";
    });
  }
  window.VPNStatusPage = sessions;

  function events() {
    fetch("/api/events?limit=150", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        var tb = document.querySelector("#events tbody");
        C.clear(tb);
        if (!d.events.length) {
          var td = h("td", "muted", "Noch keine Ereignisse.", h("tr", null, null, tb));
          td.colSpan = 8;
          return;
        }
        d.events.forEach(function (e) {
          var tr = h("tr", null, null, tb);
          var dt = new Date(e.t * 1000);
          h("td", "nowrap", dt.toLocaleDateString("de-DE") + " " + dt.toLocaleTimeString("de-DE"), tr);
          var ev = h("td", null, null, tr);
          h("span", "badge " + (e.type === "connect" ? "ok" : ""), e.type === "connect" ? "angemeldet" : "abgemeldet", ev);
          h("td", null, e.user || "", tr);
          h("td", null, e.proto || "", tr);
          h("td", null, e.vip || "", tr);
          h("td", null, e.remote || "", tr);
          h("td", "num", e.duration !== undefined ? C.fmtDuration(e.duration) : "", tr);
          h("td", "num", e.type === "disconnect" ? "↓ " + C.fmtBytes(e.down) + " · ↑ " + C.fmtBytes(e.up) : "", tr);
        });
      })
      .catch(function () { /* ignorieren */ });
  }
  events();
  setInterval(events, 30000);
})();
