/**
 * Ticket Bot Detection — Client Signal Collector
 * Drop as a single <script> tag in your checkout page.
 * No dependencies. ~3KB minified.
 */
(function () {
  "use strict";

  const SESSION_TOKEN =
    document.cookie.match(/session_token=([^;]+)/)?.[1] ||
    document.querySelector("meta[name=session-token]")?.content;

  if (!SESSION_TOKEN) return;

  const t0 = Date.now();
  const signals = {
    mousePath: [],
    scrollEvents: 0,
    hoverMap: {},
    keyIntervals: [],
    lastKey: 0,
    selectionAt: null,
    selectionMethod: null,
    checkoutAt: null,
    focusEvents: 0,
  };

  /* ── Mouse trajectory ────────────────────────────── */
  let lastSample = 0;
  document.addEventListener("mousemove", (e) => {
    const now = Date.now();
    if (now - lastSample > 40) {
      signals.mousePath.push([e.clientX, e.clientY, now - t0]);
      lastSample = now;
    }
  });

  /* ── Scroll depth ────────────────────────────────── */
  document.addEventListener("scroll", () => signals.scrollEvents++, {
    passive: true,
  });

  /* ── Ticket hover tracking ───────────────────────── */
  document.querySelectorAll("[data-ticket]").forEach((el) => {
    el.addEventListener("mouseenter", () => {
      signals.hoverMap[el.dataset.ticket] = Date.now();
    });
    el.addEventListener("mouseleave", () => {
      const s = signals.hoverMap[el.dataset.ticket];
      if (typeof s === "number" && s > 1e12)
        signals.hoverMap[el.dataset.ticket] = Date.now() - s;
    });
  });

  /* ── Keystroke timing ────────────────────────────── */
  document.addEventListener("keydown", () => {
    const now = Date.now();
    if (signals.lastKey) signals.keyIntervals.push(now - signals.lastKey);
    signals.lastKey = now;
  });

  /* ── Selection detection ─────────────────────────── */
  document.querySelectorAll("[data-ticket]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (!signals.selectionAt) {
        signals.selectionMethod = e.isTrusted ? "click" : "dom_inject";
        signals.selectionAt = Date.now();
        beacon("selection");
      }
    });
  });

  /* ── Checkout button ─────────────────────────────── */
  const checkoutBtn = document.querySelector(
    "#checkout-btn, [data-action=checkout]"
  );
  checkoutBtn?.addEventListener("click", (e) => {
    signals.checkoutAt = Date.now();
    if (!signals.selectionMethod)
      signals.selectionMethod = e.isTrusted ? "click" : "dom_inject";
    beacon("checkout");
  });

  /* ── Focus events (tab-navigation bots miss these) ── */
  document.addEventListener("focus", () => signals.focusEvents++, true);

  /* ── Canvas fingerprint ──────────────────────────── */
  function canvasFingerprint() {
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("BotDetect,v1.0", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("BotDetect,v1.0", 4, 17);
      return btoa(c.toDataURL()).slice(0, 64);
    } catch {
      return "unavailable";
    }
  }

  /* ── Entropy calculation ─────────────────────────── */
  function mouseEntropy(path) {
    if (path.length < 4) return 0;
    const angles = [];
    for (let i = 1; i < path.length - 1; i++) {
      const a1 = Math.atan2(
        path[i][1] - path[i - 1][1],
        path[i][0] - path[i - 1][0]
      );
      const a2 = Math.atan2(
        path[i + 1][1] - path[i][1],
        path[i + 1][0] - path[i][0]
      );
      angles.push(((a2 - a1 + Math.PI) / (2 * Math.PI)) * 8);
    }
    const bins = new Array(8).fill(0);
    angles.forEach((a) => bins[Math.floor(a) % 8]++);
    const n = angles.length;
    const h = -bins.reduce((acc, c) => {
      const p = c / n;
      return p > 0 ? acc + p * Math.log2(p) : acc;
    }, 0);
    return parseFloat((h / Math.log2(8)).toFixed(4));
  }

  function keystrokeRegularity(intervals) {
    if (intervals.length < 3) return 0;
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance =
      intervals.map((t) => (t - mean) ** 2).reduce((a, b) => a + b, 0) /
      intervals.length;
    const cv = Math.sqrt(variance) / mean;
    return parseFloat(Math.max(0, Math.min(1, 1 - cv)).toFixed(4));
  }

  /* ── Beacon sender ───────────────────────────────── */
  function beacon(trigger) {
    const hoverTotal =
      Object.values(signals.hoverMap)
        .filter((v) => typeof v === "number" && v < 1e6)
        .reduce((a, b) => a + b, 0) / 1000;

    const payload = JSON.stringify({
      session_token: SESSION_TOKEN,
      trigger,
      time_to_select: signals.selectionAt
        ? +((signals.selectionAt - t0) / 1000).toFixed(3)
        : null,
      time_to_checkout:
        signals.checkoutAt && signals.selectionAt
          ? +((signals.checkoutAt - signals.selectionAt) / 1000).toFixed(3)
          : null,
      mouse_entropy: mouseEntropy(signals.mousePath),
      mouse_path_length: signals.mousePath.length,
      scroll_events: signals.scrollEvents,
      focus_events: signals.focusEvents,
      hover_duration: +hoverTotal.toFixed(3),
      keystroke_regularity: keystrokeRegularity(signals.keyIntervals),
      selection_method: signals.selectionMethod,
      canvas_fp: canvasFingerprint(),
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      tz_offset: new Date().getTimezoneOffset(),
    });

    // sendBeacon is fire-and-forget — won't block checkout
    navigator.sendBeacon?.("/api/session/signal", payload) ||
      fetch("/api/session/signal", {
        method: "POST",
        body: payload,
        keepalive: true,
        headers: { "Content-Type": "application/json" },
      });
  }
})();
