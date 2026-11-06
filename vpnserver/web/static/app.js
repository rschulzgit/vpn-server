// VPN-Server Weboberflaeche - kleine Helfer ohne externe Abhaengigkeiten
(function () {
  "use strict";

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  }

  // Kopieren in die Zwischenablage
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest(".copy");
    if (!btn) return;
    ev.preventDefault();
    var text = btn.getAttribute("data-copy");
    if (text === null) {
      var target = document.getElementById(btn.getAttribute("data-target"));
      text = target ? (target.value || target.textContent) : "";
    }
    function done() {
      var old = btn.textContent;
      btn.classList.add("done");
      btn.textContent = "kopiert";
      setTimeout(function () { btn.classList.remove("done"); btn.textContent = old; }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
    } else { fallback(text); done(); }
  });

  function fallback(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignorieren */ }
    document.body.removeChild(ta);
  }

  // Tabs (Hauptreiter und Unterreiter)
  function activate(group, name) {
    document.querySelectorAll('[data-tabgroup="' + group + '"] > button').forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-tab") === name);
    });
    document.querySelectorAll('[data-tabpanel="' + group + '"]').forEach(function (p) {
      p.classList.toggle("active", p.getAttribute("data-name") === name);
    });
  }
  document.querySelectorAll("[data-tabgroup]").forEach(function (bar) {
    var group = bar.getAttribute("data-tabgroup");
    var buttons = bar.querySelectorAll(":scope > button");
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        activate(group, b.getAttribute("data-tab"));
        if (group === "main") { history.replaceState(null, "", "#" + b.getAttribute("data-tab")); }
      });
    });
    var initial = buttons.length ? buttons[0].getAttribute("data-tab") : null;
    if (group === "main" && location.hash) {
      var h = location.hash.substring(1);
      if (bar.querySelector('[data-tab="' + h + '"]')) initial = h;
    }
    if (initial) activate(group, initial);
  });

  // Bestaetigungsdialoge
  document.addEventListener("submit", function (ev) {
    var msg = ev.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) ev.preventDefault();
  });

  // Passwort anzeigen
  document.querySelectorAll("[data-toggle-pw]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-toggle-pw"));
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
    });
  });

  // Oeffentliche IP ermitteln
  document.querySelectorAll("[data-detect-ip]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-detect-ip"));
      btn.disabled = true;
      var old = btn.textContent;
      btn.textContent = "Ermittle ...";
      fetch("/api/detect-ip", { method: "POST", headers: { "X-CSRF-Token": csrf() }, credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ip) { input.value = d.ip; } else { alert("Die oeffentliche IP konnte nicht ermittelt werden."); }
        })
        .catch(function () { alert("Fehler bei der Abfrage."); })
        .finally(function () { btn.disabled = false; btn.textContent = old; });
    });
  });

  // DynDNS-Felder je Anbieter
  var provider = document.getElementById("ddns-provider");
  function ddnsFields() {
    if (!provider) return;
    var p = provider.value;
    document.querySelectorAll("[data-ddns]").forEach(function (el) {
      var list = el.getAttribute("data-ddns").split(" ");
      el.classList.toggle("hidden", list.indexOf(p) === -1);
    });
  }
  if (provider) { provider.addEventListener("change", ddnsFields); ddnsFields(); }

  // Netzwerk: statische Felder ein-/ausblenden
  var method = document.getElementById("net-method");
  function netFields() {
    if (!method) return;
    document.querySelectorAll("[data-static]").forEach(function (el) {
      el.classList.toggle("hidden", method.value !== "static");
    });
  }
  if (method) { method.addEventListener("change", netFields); netFields(); }

  // ---------------------------------------------------------------- Seitenleiste (mobil)
  var sidebar = document.getElementById("sidebar");
  var scrim = document.getElementById("scrim");
  var menuBtn = document.getElementById("menu-btn");
  function setNav(open) {
    if (!sidebar) return;
    sidebar.classList.toggle("open", open);
    scrim.classList.toggle("open", open);
    menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
  }
  if (menuBtn) {
    menuBtn.addEventListener("click", function () { setNav(!sidebar.classList.contains("open")); });
    scrim.addEventListener("click", function () { setNav(false); });
    document.addEventListener("keydown", function (ev) { if (ev.key === "Escape") setNav(false); });
  }

  // ---------------------------------------------------------------- Kopfzeile: Durchsatz + Status
  var nf1 = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });
  function rate(bps) {
    var b = (bps || 0) * 8;
    if (b >= 1e9) return nf1.format(b / 1e9) + " Gbit/s";
    if (b >= 1e6) return nf1.format(b / 1e6) + " Mbit/s";
    if (b >= 1e3) return Math.round(b / 1e3) + " kbit/s";
    return Math.round(b) + " bit/s";
  }
  window.VPNTopbar = function (d) {
    var bar = document.getElementById("topbar-live");
    if (!bar || !d) return;
    var pts = d.points || [];
    var last = pts.length ? pts[pts.length - 1] : [0, 0, 0];
    document.getElementById("tb-down").textContent = "↓ " + rate(last[1]);
    document.getElementById("tb-up").textContent = "↑ " + rate(last[2]);
    var pill = document.getElementById("tb-health");
    var problems = d.problems || [];
    pill.className = "pill " + (problems.length ? "err" : "ok");
    pill.textContent = problems.length ? problems.length + " Dienst(e) gestört" : "Alle Dienste laufen";
    pill.title = problems.join(", ");
    bar.hidden = false;
  };
  function topbarPoll() {
    if (window.VPN_LIVE_PAGE || document.hidden || !document.getElementById("topbar-live")) return;
    fetch("/api/live", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        window.VPNTopbar(d);
        if (d && window.VPNStatusPage) window.VPNStatusPage(d);
      })
      .catch(function () { /* ignorieren */ });
  }
  if (document.getElementById("topbar-live")) {
    setTimeout(topbarPoll, 50);
    setInterval(topbarPoll, 5000);
  }
})();
