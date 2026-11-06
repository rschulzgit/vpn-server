// VPN-Server: Fortschritt des Software-Updates live anzeigen
(function () {
  "use strict";
  var box = document.getElementById("app-update-box");
  if (!box) return;
  var labels = { running: "läuft", done: "fertig", failed: "fehlgeschlagen" };
  var wasRunning = box.getAttribute("data-state") === "running";
  function poll() {
    fetch("/api/update/status", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        box.classList.toggle("hidden", d.state === "idle");
        var st = document.getElementById("app-update-state");
        st.textContent = labels[d.state] || d.state;
        st.className = "badge " + (d.state === "done" ? "ok" : d.state === "failed" ? "err" : "warn");
        document.getElementById("app-update-msg").textContent = d.message || "";
        var log = document.getElementById("app-update-log");
        log.textContent = d.log || "";
        log.scrollTop = log.scrollHeight;
        if (wasRunning && d.state !== "running") { setTimeout(function () { location.reload(); }, 1500); }
        wasRunning = d.state === "running";
      })
      .catch(function () { /* Weboberflaeche startet gerade neu */ });
  }
  if (wasRunning) {
    setInterval(poll, 3000);
    poll();
  }
})();
