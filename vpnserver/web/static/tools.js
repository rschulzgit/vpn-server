// VPN-Server: Werkzeuge (Ausgabe per fetch, ohne Seitenwechsel)
(function () {
  "use strict";
  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  document.querySelectorAll("form[data-tool]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var tool = form.getAttribute("data-tool");
      var out = document.querySelector('[data-out="' + tool + '"]');
      var btn = form.querySelector('button[type="submit"]');
      var label = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Läuft …";
      if (out) { out.classList.remove("hidden"); out.textContent = "Bitte warten …"; }
      fetch("/api/tools/" + tool, { method: "POST", body: new FormData(form), credentials: "same-origin",
                                    headers: { "X-CSRF-Token": csrf } })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (tool === "speedtest" && d.ok) {
            var r = d.result;
            document.getElementById("speed-result").classList.remove("hidden");
            document.getElementById("sp-lat").textContent = String(r.latency_ms).replace(".", ",") + " ms";
            document.getElementById("sp-down").textContent = String(r.down_mbit).replace(".", ",") + " Mbit/s";
            document.getElementById("sp-up").textContent = String(r.up_mbit).replace(".", ",") + " Mbit/s";
            if (out) out.classList.add("hidden");
            return;
          }
          if (out) out.textContent = d.output || (d.ok ? "Fertig." : "Fehler.");
        })
        .catch(function () { if (out) out.textContent = "Fehler bei der Anfrage."; })
        .finally(function () { btn.disabled = false; btn.textContent = label; });
    });
  });
})();
