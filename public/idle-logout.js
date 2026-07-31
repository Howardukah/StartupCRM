/**
 * idle-logout.js — Centralized idle/inactivity auto-logout module
 *
 * Usage:
 *   initIdleLogout({
 *     idleLimitMinutes   : 30,
 *     warningLeadMinutes : 5,
 *     onLogout           : () => ...,
 *     isBusy             : () => ...,
 *   });
 *
 * Cross-tab sync: any activity in any tab resets the idle timer in all tabs.
 * The storage listener on OTHER tabs reads the new value into memory only —
 * it does NOT write back to localStorage, so there is no feedback loop.
 */
(function (global) {
  'use strict';

  const LS_KEY = 'crm-idle-last-activity';

  global.initIdleLogout = function initIdleLogout({
    idleLimitMinutes   = 30,
    warningLeadMinutes = 5,
    onLogout           = () => { window.location.href = '/'; },
    isBusy             = () => false,
  } = {}) {

    const IDLE_LIMIT_MS = idleLimitMinutes   * 60 * 1000;
    const WARN_LEAD_MS  = warningLeadMinutes  * 60 * 1000;
    const WARN_AT_MS    = IDLE_LIMIT_MS - WARN_LEAD_MS;
    const WARN_SECS     = warningLeadMinutes  * 60;

    const ac = new AbortController();
    const { signal } = ac;

    let countdownInterval = null;
    let warningActive     = false;
    let destroyed         = false;

    // ── localStorage helpers ───────────────────────────────────────────────

    function readLastActivity() {
      try { const v = localStorage.getItem(LS_KEY); return v ? parseInt(v, 10) : Date.now(); }
      catch { return Date.now(); }
    }

    function writeLastActivity(ts) {
      try { localStorage.setItem(LS_KEY, String(ts)); } catch { /* storage unavailable */ }
    }

    function getElapsedMs() { return Date.now() - readLastActivity(); }

    // ── Audio chime ────────────────────────────────────────────────────────

    function playChime() {
      try {
        const AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return;
        const ctx = new AC();
        if (ctx.state === 'suspended') {
          ctx.resume();
        }
        const osc1 = ctx.createOscillator(); const osc2 = ctx.createOscillator();
        const gain = ctx.createGain();
        osc1.type = 'sine'; osc2.type = 'triangle';
        osc1.frequency.value = 1108.7; osc2.frequency.value = 1661.2;
        osc1.connect(gain); osc2.connect(gain); gain.connect(ctx.destination);
        gain.gain.setValueAtTime(0, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0.15, ctx.currentTime + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
        osc1.start(ctx.currentTime); osc2.start(ctx.currentTime);
        osc1.stop(ctx.currentTime + 0.6); osc2.stop(ctx.currentTime + 0.6);
      } catch { /* audio unavailable */ }
    }

    // ── Toast ──────────────────────────────────────────────────────────────

    function showWarningToast() {
      if (warningActive) return;
      warningActive = true;

      playChime();

      if (window.Notification && Notification.permission === 'granted') {
        try { new Notification('Session Expiring', { body: 'You will be logged out in ' + warningLeadMinutes + ' minutes due to inactivity.' }); } catch { /* revoked */ }
      }

      let container = document.getElementById('slide-toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'slide-toast-container';
        container.className = 'slide-toast-container';
        document.body.appendChild(container);
      }

      const el = document.createElement('div');
      el.id = 'inactivity-warning-toast';
      el.className = 'slide-toast slide-toast--accent glossy-toast';
      el.style.cssText = 'position:relative;padding:12px 16px;background:var(--surface);border:1px solid var(--border);box-shadow:0 10px 28px -4px rgba(0,0,0,0.22);border-radius:12px;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);cursor:pointer;user-select:none;max-width:320px;';
      el.title = 'Click anywhere to stay logged in';
      el.onclick = function(e) { e.stopPropagation(); resetIdle(true); };

      el.innerHTML =
        '<div class="slide-toast__icon-wrap" style="background:color-mix(in srgb, var(--accent,#00A8B5) 15%, transparent);color:var(--accent,#00A8B5);border:1px solid color-mix(in srgb, var(--accent,#00A8B5) 30%, transparent);width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">' +
          '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' +
        '</div>' +
        '<div class="slide-toast__content" style="flex:1;min-width:0;">' +
          '<div class="slide-toast__title" style="font-weight:700;font-size:13px;color:var(--text);line-height:1.2;">Inactivity Warning</div>' +
          '<div class="slide-toast__desc" style="font-size:11.5px;color:var(--text-muted);margin-top:3px;line-height:1.35;">You will be logged out in <strong id="inactivity-countdown" style="color:var(--accent,#00A8B5);font-variant-numeric:tabular-nums;font-weight:700;">' + String(Math.floor(WARN_SECS / 60)).padStart(2, '0') + ':00</strong> due to inactivity.</div>' +
        '</div>';

      container.appendChild(el);
      setTimeout(function() { el.classList.add('show'); }, 50);

      // Countdown reads elapsed time directly — stays accurate even after throttled background ticks
      countdownInterval = setInterval(function() {
        var elapsed  = getElapsedMs();
        var msLeft   = Math.max(0, IDLE_LIMIT_MS - elapsed);
        var secsLeft = Math.ceil(msLeft / 1000);
        var m = Math.floor(secsLeft / 60).toString().padStart(2, '0');
        var s = (secsLeft % 60).toString().padStart(2, '0');
        var cdEl = document.getElementById('inactivity-countdown');
        if (cdEl) cdEl.textContent = m + ':' + s;
      }, 1000);
    }

    function removeWarningToast(resumed) {
      warningActive = false;
      if (countdownInterval) { clearInterval(countdownInterval); countdownInterval = null; }
      var el = document.getElementById('inactivity-warning-toast');
      if (el) { el.classList.remove('show'); setTimeout(function() { el.remove(); }, 450); }
      if (resumed && typeof showToast === 'function') showToast('Session resumed. Welcome back!', 'success');
    }

    // ── Core check (interval + wakeup events both call this) ──────────────

    function checkNow() {
      if (destroyed) return;
      var elapsed = getElapsedMs();

      // Show warning — gated on isBusy() so a countdown never appears over an active upload
      if (elapsed >= WARN_AT_MS && elapsed < IDLE_LIMIT_MS && !warningActive) {
        if (!isBusy()) showWarningToast();
        return;
      }

      if (elapsed >= IDLE_LIMIT_MS) {
        destroy();
        removeWarningToast(false);
        if (isBusy()) {
          // Defer logout until the busy operation finishes
          var busyPoll = setInterval(function() {
            if (!isBusy()) { clearInterval(busyPoll); onLogout(); }
          }, 5000);
        } else {
          onLogout();
        }
      }
    }

    // ── Main interval ──────────────────────────────────────────────────────

    var idleInterval = setInterval(checkNow, 1000);

    // ── Activity reset ─────────────────────────────────────────────────────

    function resetIdle(force) {
      if (destroyed) return;
      var wasWarning = warningActive;
      // While warning toast is active, passive mouse movements do not auto-dismiss;
      // user must click 'Stay Logged In', click anywhere, or press a key.
      if (wasWarning && !force) return;
      writeLastActivity(Date.now()); // only this tab writes; other tabs read via storage event
      if (wasWarning) removeWarningToast(true);
    }

    // Passive timers update activity timestamp; when warning is active, click/keydown triggers resetIdle(true)
    window.addEventListener('mousemove',  function() { if (!warningActive) resetIdle(false); }, { passive: true, signal: signal });
    window.addEventListener('scroll',     function() { if (!warningActive) resetIdle(false); }, { passive: true, signal: signal });
    window.addEventListener('touchmove',  function() { if (!warningActive) resetIdle(false); }, { passive: true, signal: signal });
    window.addEventListener('click',      function() { resetIdle(true); },  { passive: true, signal: signal });
    window.addEventListener('keydown',    function() { resetIdle(true); },  { passive: true, signal: signal });
    window.addEventListener('touchstart', function() { resetIdle(true); },  { passive: true, signal: signal });

    // ── Cross-tab sync — READ ONLY, no write-back, no feedback loop ────────
    window.addEventListener('storage', function(e) {
      if (e.key !== LS_KEY) return;
      if (warningActive) removeWarningToast(false);
    }, { signal: signal });

    // ── Immediate re-check on tab resume / mobile wakeup ──────────────────

    function onResume() {
      if (destroyed) return;
      if (warningActive) {
        playChime(); // Replay chime on tab focus so user hears audio upon switching back
      }
      checkNow();
    }

    document.addEventListener('visibilitychange', function() {
      if (document.visibilityState === 'visible') onResume();
    }, { signal: signal });
    window.addEventListener('focus',    onResume, { signal: signal });
    window.addEventListener('pageshow', onResume, { signal: signal });

    // ── Check existing activity timestamp or initialize if missing ────────
    var existingTs = localStorage.getItem(LS_KEY);
    if (!existingTs) {
      writeLastActivity(Date.now());
    } else {
      // Re-evaluate immediately against pre-existing activity timestamp
      checkNow();
    }

    // ── Teardown ───────────────────────────────────────────────────────────

    function destroy() {
      if (destroyed) return;
      destroyed = true;
      clearInterval(idleInterval);
      ac.abort(); // removes ALL listeners registered with { signal }
    }

    return { destroy: destroy };
  };

})(window);
