// VPN-Server: kleine SVG-Diagrammbibliothek ohne externe Abhaengigkeiten.
// Linien-/Flaechendiagramm mit Fadenkreuz, gestapelte Saeulen mit Tooltip,
// Balkenliste, segmentierter Balken, Sparkline. Texte immer per textContent.
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var nf1 = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });
  var nf0 = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 0 });

  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(e);
    return e;
  }
  function h(tag, cls, text, parent) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---------------------------------------------------------------- Formate
  function fmtRate(bytesPerSec) {
    var b = (bytesPerSec || 0) * 8;
    if (b >= 1e9) return nf1.format(b / 1e9) + " Gbit/s";
    if (b >= 1e6) return nf1.format(b / 1e6) + " Mbit/s";
    if (b >= 1e3) return nf0.format(b / 1e3) + " kbit/s";
    return nf0.format(b) + " bit/s";
  }
  function fmtBytes(n) {
    n = n || 0;
    if (n >= 1e12) return nf1.format(n / 1e12) + " TB";
    if (n >= 1e9) return nf1.format(n / 1e9) + " GB";
    if (n >= 1e6) return nf1.format(n / 1e6) + " MB";
    if (n >= 1e3) return nf0.format(n / 1e3) + " kB";
    return nf0.format(n) + " B";
  }
  function fmtDuration(s) {
    s = Math.max(0, Math.floor(s || 0));
    var d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), mm = Math.floor(s % 3600 / 60);
    if (d) return d + " T " + hh + " Std";
    if (hh) return hh + " Std " + mm + " Min";
    if (mm) return mm + " Min";
    return s + " s";
  }
  function clock(t) {
    var d = new Date(t * 1000);
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0") +
      ":" + String(d.getSeconds()).padStart(2, "0");
  }
  function niceStep(max, ticks) {
    var raw = max / ticks;
    var p = Math.pow(10, Math.floor(Math.log10(raw)));
    var n = raw / p;
    var m = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
    return m * p;
  }

  // Tooltip-Helfer: Werte zuerst, Bezeichnung danach, Reihen mit Linien-Schluessel
  function tooltip(container) {
    var tip = h("div", "tooltip", null, container);
    tip.hidden = true;
    tip.setAttribute("role", "status");
    return {
      show: function (title, rows, x, y) {
        clear(tip);
        h("div", "tt-title", title, tip);
        rows.forEach(function (r) {
          var row = h("div", "tt-row", null, tip);
          h("i", "lg-line " + r.cls, null, row);
          h("strong", null, r.value, row);
          h("span", null, r.label, row);
        });
        tip.hidden = false;
        var cw = container.clientWidth, tw = tip.offsetWidth;
        var left = x + 14;
        if (left + tw > cw) left = Math.max(0, x - tw - 14);
        tip.style.left = left + "px";
        tip.style.top = Math.max(0, y - 10) + "px";
      },
      hide: function () { tip.hidden = true; }
    };
  }

  // ---------------------------------------------------------------- Liniendiagramm
  // series: [{key, label, cls}] ; points: [[t, v1, v2, ...]] (Bytes/s)
  function LineChart(container, opts) {
    this.c = container;
    this.opts = opts;
    this.height = opts.height || 220;
    this.points = [];
    this.svg = el("svg", { role: "img", "aria-label": opts.label || "Diagramm" }, container);
    this.tip = tooltip(container);
    var self = this;
    window.addEventListener("resize", function () { self.render(); });
  }
  LineChart.prototype.update = function (points) { this.points = points || []; this.render(); };
  LineChart.prototype.render = function () {
    var self = this, o = this.opts, svg = this.svg, pts = this.points;
    var W = this.c.clientWidth || 600, H = this.height;
    var m = { l: 64, r: 10, t: 10, b: 24 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("height", H);
    clear(svg);
    var now = pts.length ? pts[pts.length - 1][0] : Math.floor(Date.now() / 1000);
    var span = o.span || 300, t0 = now - span;
    var max = 0;
    pts.forEach(function (p) { o.series.forEach(function (s, i) { max = Math.max(max, p[i + 1] * 8); }); });
    max = Math.max(max, 1e6);  // mindestens 1 Mbit/s Skala
    var step = niceStep(max, 4), top = Math.ceil(max / step) * step;
    function x(t) { return m.l + (t - t0) / span * pw; }
    function y(v) { return m.t + ph - (v * 8) / top * ph; }
    for (var v = 0; v <= top + 1e-6; v += step) {
      var yy = m.t + ph - v / top * ph;
      el("line", { x1: m.l, x2: W - m.r, y1: yy, y2: yy, "class": v === 0 ? "base-line" : "grid-line" }, svg);
      var tk = el("text", { x: m.l - 8, y: yy + 4, "text-anchor": "end", "class": "tick" }, svg);
      tk.textContent = fmtRate(v / 8).replace(" ", " ");
    }
    for (var tt = Math.ceil(t0 / 60) * 60; tt <= now; tt += 60) {
      var lab = el("text", { x: x(tt), y: H - 6, "text-anchor": "middle", "class": "tick" }, svg);
      lab.textContent = clock(tt).slice(0, 5);
    }
    if (pts.length < 2) {
      var e = el("text", { x: m.l + pw / 2, y: m.t + ph / 2, "text-anchor": "middle", "class": "tick" }, svg);
      e.textContent = o.empty || "Noch keine Messwerte";
      return;
    }
    o.series.forEach(function (s, i) {
      var line = "", area = "";
      pts.forEach(function (p, j) {
        var px = x(p[0]).toFixed(1), py = y(p[i + 1]).toFixed(1);
        line += (j ? "L" : "M") + px + " " + py;
      });
      area = line + "L" + x(pts[pts.length - 1][0]).toFixed(1) + " " + (m.t + ph) +
        "L" + x(pts[0][0]).toFixed(1) + " " + (m.t + ph) + "Z";
      el("path", { d: area, "class": "area f-" + s.key }, svg);
      el("path", { d: line, "class": "line s-" + s.key }, svg);
    });
    var cross = el("line", { y1: m.t, y2: m.t + ph, "class": "crosshair", visibility: "hidden" }, svg);
    var dots = o.series.map(function (s) { return el("circle", { r: 4.5, "class": "hover-dot f-" + s.key, visibility: "hidden" }, svg); });
    var hit = el("rect", { x: m.l, y: m.t, width: pw, height: ph, "class": "hit", tabindex: 0 }, svg);
    function at(i) {
      var p = pts[i], px = x(p[0]);
      cross.setAttribute("x1", px); cross.setAttribute("x2", px); cross.setAttribute("visibility", "visible");
      dots.forEach(function (d, k) { d.setAttribute("cx", px); d.setAttribute("cy", y(p[k + 1])); d.setAttribute("visibility", "visible"); });
      self.tip.show(clock(p[0]), o.series.map(function (s, k) {
        return { cls: "bg-" + s.key, value: fmtRate(p[k + 1]), label: s.label };
      }), px * (self.c.clientWidth / W), m.t);
      self.idx = i;
    }
    function nearest(clientX) {
      var r = svg.getBoundingClientRect();
      var px = (clientX - r.left) * (W / r.width);
      var t = t0 + (px - m.l) / pw * span, best = 0, bd = Infinity;
      pts.forEach(function (p, i) { var d = Math.abs(p[0] - t); if (d < bd) { bd = d; best = i; } });
      return best;
    }
    function off() { cross.setAttribute("visibility", "hidden"); dots.forEach(function (d) { d.setAttribute("visibility", "hidden"); }); self.tip.hide(); }
    hit.addEventListener("pointermove", function (ev) { at(nearest(ev.clientX)); });
    hit.addEventListener("pointerleave", off);
    hit.addEventListener("focus", function () { at(pts.length - 1); });
    hit.addEventListener("blur", off);
    hit.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowLeft") at(Math.max(0, (self.idx || pts.length - 1) - 1));
      if (ev.key === "ArrowRight") at(Math.min(pts.length - 1, (self.idx || 0) + 1));
    });
  };

  // ---------------------------------------------------------------- Gestapelte Saeulen
  // data: [{label, down, up}]
  function ColumnChart(container, opts) {
    this.c = container;
    this.opts = opts || {};
    this.height = this.opts.height || 240;
    this.data = [];
    this.svg = el("svg", { role: "img", "aria-label": this.opts.label || "Saeulendiagramm" }, container);
    this.tip = tooltip(container);
    var self = this;
    window.addEventListener("resize", function () { self.render(); });
  }
  ColumnChart.prototype.update = function (data) { this.data = data || []; this.render(); };
  ColumnChart.prototype.render = function () {
    var self = this, svg = this.svg, data = this.data;
    var W = this.c.clientWidth || 600, H = this.height;
    var m = { l: 56, r: 6, t: 10, b: 26 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("height", H);
    clear(svg);
    var max = 0;
    data.forEach(function (d) { max = Math.max(max, d.down + d.up); });
    var empty = max === 0;
    max = Math.max(max, 1e6);
    var step = niceStep(max, 4), top = Math.ceil(max / step) * step;
    for (var v = 0; v <= top + 1e-6; v += step) {
      var yy = m.t + ph - v / top * ph;
      el("line", { x1: m.l, x2: W - m.r, y1: yy, y2: yy, "class": v === 0 ? "base-line" : "grid-line" }, svg);
      el("text", { x: m.l - 8, y: yy + 4, "text-anchor": "end", "class": "tick" }, svg).textContent = fmtBytes(v);
    }
    var n = data.length || 1, band = pw / n, bw = Math.max(3, Math.min(24, band * 0.62));
    var every = Math.ceil(n / Math.max(1, Math.floor(pw / 52)));
    data.forEach(function (d, i) {
      var cx = m.l + band * i + band / 2;
      if (i % every === 0) el("text", { x: cx, y: H - 8, "text-anchor": "middle", "class": "tick" }, svg).textContent = d.label;
    });
    if (empty) {
      el("text", { x: m.l + pw / 2, y: m.t + ph / 2, "text-anchor": "middle", "class": "tick" }, svg)
        .textContent = self.opts.empty || "Noch kein Datenverkehr in diesem Zeitraum";
    }
    data.forEach(function (d, i) {
      var cx = m.l + band * i + band / 2, x0 = cx - bw / 2, base = m.t + ph;
      var g = el("g", { "class": "col" }, svg);
      var hDown = d.down / top * ph, hUp = d.up / top * ph;
      var segs = [];
      if (hDown > 0) segs.push({ h: hDown, cls: "f-down" });
      if (hUp > 0) segs.push({ h: hUp, cls: "f-up" });
      var yCur = base;
      segs.forEach(function (s, k) {
        var gap = k > 0 ? 2 : 0;
        var hh = Math.max(1, s.h - gap), y1 = yCur - gap - hh;
        var r = k === segs.length - 1 ? Math.min(4, hh, bw / 2) : 0;
        var p = "M" + x0 + " " + (y1 + hh) + "V" + (y1 + r) +
          (r ? "Q" + x0 + " " + y1 + " " + (x0 + r) + " " + y1 : "") +
          "H" + (x0 + bw - r) + (r ? "Q" + (x0 + bw) + " " + y1 + " " + (x0 + bw) + " " + (y1 + r) : "") +
          "V" + (y1 + hh) + "Z";
        el("path", { d: p, "class": s.cls }, g);
        yCur = y1;
      });
      var hit = el("rect", { x: m.l + band * i, y: m.t, width: band, height: ph, "class": "hit", tabindex: 0 }, svg);
      function show() {
        g.classList.add("hover");
        self.tip.show(d.label, [
          { cls: "bg-down", value: fmtBytes(d.down), label: "Download" },
          { cls: "bg-up", value: fmtBytes(d.up), label: "Upload" }
        ], cx * (self.c.clientWidth / W), m.t);
      }
      function hide() { g.classList.remove("hover"); self.tip.hide(); }
      hit.addEventListener("pointerenter", show);
      hit.addEventListener("pointerleave", hide);
      hit.addEventListener("focus", show);
      hit.addEventListener("blur", hide);
    });
  };

  // ---------------------------------------------------------------- Balkenliste
  // rows: [{name, down, up, note}]
  function barList(container, rows, opts) {
    opts = opts || {};
    clear(container);
    if (!rows.length) { h("div", "chart-empty", opts.empty || "Keine Daten", container); return; }
    var max = 0;
    rows.forEach(function (r) { max = Math.max(max, r.down + r.up); });
    rows.slice(0, opts.limit || 8).forEach(function (r) {
      var row = h("div", "bl-row", null, container);
      var name = h("div", "bl-name", r.name, row);
      if (r.note) h("small", "muted", r.note, name);
      var track = h("div", "bl-track", null, row);
      var total = r.down + r.up;
      [["down", r.down, "Download"], ["up", r.up, "Upload"]].forEach(function (s) {
        if (!s[1]) return;
        var seg = h("div", "bl-seg bg-" + s[0], null, track);
        seg.style.width = (max ? s[1] / max * 100 : 0) + "%";
        seg.title = s[2] + ": " + fmtBytes(s[1]);
      });
      h("div", "bl-val", fmtBytes(total), row);
    });
  }

  // ---------------------------------------------------------------- Segmentierter Balken
  // parts: [{name, value, slot}] ; Beschriftung nur, wenn sie hineinpasst
  function segBar(container, legend, parts) {
    clear(container); clear(legend);
    var total = parts.reduce(function (a, p) { return a + p.value; }, 0);
    container.className = total ? "segbar" : "segbar-empty";
    parts.forEach(function (p) {
      if (!p.value) return;
      var share = p.value / total;
      var b = h("div", "sb bg-p" + p.slot + (p.slot === 4 ? " ink-dark" : ""), null, container);
      b.style.flex = String(p.value);
      b.title = p.name + ": " + p.value + " (" + Math.round(share * 100) + " %)";
      b.setAttribute("aria-label", b.title);
      var label = String(p.value);
      if (container.clientWidth * share > label.length * 8 + 16) b.textContent = label;
      var lg = h("span", "lg", null, legend);
      h("i", "lg-box bg-p" + p.slot, null, lg);
      h("span", null, p.name, lg);
    });
    if (!total) h("span", "muted", "Keine aktiven Verbindungen", legend);
  }

  // ---------------------------------------------------------------- Sparkline
  function sparkline(svg, values, dotCls) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var W = svg.clientWidth || 200, H = svg.clientHeight || 38;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    if (!values || values.length < 2) return;
    var max = Math.max.apply(null, values.concat([1e-9]));
    var pad = 5, n = values.length;
    function x(i) { return pad + i / (n - 1) * (W - 2 * pad); }
    function y(v) { return H - pad - v / max * (H - 2 * pad); }
    var d = "";
    values.forEach(function (v, i) { d += (i ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1); });
    el("path", { d: d + "L" + x(n - 1) + " " + (H - pad) + "L" + x(0) + " " + (H - pad) + "Z", "class": "sp-area" }, svg);
    el("path", { d: d, "class": "sp-line" }, svg);
    el("circle", { cx: x(n - 1), cy: y(values[n - 1]), r: 4, "class": dotCls || "sp-dot" }, svg);
  }

  window.VPNCharts = {
    LineChart: LineChart, ColumnChart: ColumnChart, barList: barList, segBar: segBar,
    sparkline: sparkline, fmtRate: fmtRate, fmtBytes: fmtBytes, fmtDuration: fmtDuration,
    clock: clock, h: h, clear: clear
  };
})();
