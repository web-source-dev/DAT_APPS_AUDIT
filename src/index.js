'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const PORT = Number(process.env.PORT) || 7090;
const HOST = process.env.HOST || '127.0.0.1';
const INGEST_KEY = String(process.env.TRACKINGEYE_INGEST_KEY || '').trim();
const ADMIN_PASSWORD = String(process.env.TRACKINGEYE_ADMIN_PASSWORD || '').trim();
const DATA_DIR = path.join(__dirname, '..', 'data', 'reports');
const PRESENCE_PATH = path.join(__dirname, '..', 'data', 'presence.json');
const ACTIVITY_PATH = path.join(__dirname, '..', 'data', 'activity.json');
const ALERTS_PATH = path.join(__dirname, '..', 'data', 'alerts.json');
const MAX_MESSAGE = 2000;
const MAX_SHOTS = 4;
const MAX_SHOT_BYTES = 6 * 1024 * 1024;
const COOKIE = 'te_admin';
const ONLINE_MS = 20000;
const REQUEST_MS = 90000;
// Once the app has picked a remote action up, it gets this long to finish (Open DAT is slow).
const COMMAND_RUN_MS = 3 * 60 * 1000;
const PRESENCE_KEEP_MS = 10 * 60 * 1000;
const LIVE_MAX_BYTES = 3 * 1024 * 1024;
const REMOTE_ACTIONS = [
  { type: 'open-dat', label: 'Open DAT', verb: 'open DAT' },
  {
    type: 'close-dat',
    label: 'Close DAT',
    verb: 'close DAT and open the dashboard',
    confirm: 'Close DAT on this computer and show the Dat Desk dashboard?'
  },
  { type: 'hide-dat', label: 'Hide DAT', verb: 'hide the DAT window' },
  { type: 'reload-dat', label: 'Reload DAT', verb: 'reload DAT' },
  {
    type: 'refresh-session',
    label: 'Refresh session',
    verb: 'refresh the DAT session',
    confirm: 'Refresh the DAT session on this computer? DAT closes, its cache is wiped, and it reopens with a fresh session.'
  },
  {
    type: 'sign-out',
    label: 'Sign out',
    verb: 'sign out of Dat Desk',
    confirm: 'Sign this person out of Dat Desk? DAT closes and they must sign in again.'
  },
  {
    type: 'restart-app',
    label: 'Restart app',
    verb: 'restart Dat Desk',
    confirm: 'Restart Dat Desk on this computer? It closes and opens again on the dashboard.'
  },
  {
    type: 'clear-cache',
    label: 'Clear cache',
    verb: 'clear the DAT cache',
    confirm: 'Clear the DAT cache on this computer? DAT will close, and the next open loads a fresh session.'
  },
  {
    type: 'quit-app',
    label: 'Quit app',
    verb: 'quit Dat Desk',
    danger: true,
    confirm: 'Quit Dat Desk on this computer and remove it from the tray?'
  },
  // Has its own form (email + password) on the sign-in screen, not a button.
  { type: 'sign-in', label: 'Sign in', verb: 'sign in', form: true }
];
/**
 * Passwords for queued sign-ins, by command id. Kept in memory only (never in presence.json
 * or logs) and wiped as soon as the app answers or the request expires.
 */
const commandSecrets = new Map();
const REMOTE_TYPES = new Set(REMOTE_ACTIONS.map((action) => action.type));
const liveFrames = new Map();
const liveWatchers = new Map();
const liveSessions = new Map();

if (!INGEST_KEY || !ADMIN_PASSWORD) {
  console.error('[TRACKINGEYE] Set TRACKINGEYE_INGEST_KEY and TRACKINGEYE_ADMIN_PASSWORD in .env');
  process.exit(1);
}

const adminCookie = crypto
  .createHmac('sha256', ADMIN_PASSWORD)
  .update('trackingeye-admin')
  .digest('hex');

fs.mkdirSync(DATA_DIR, { recursive: true });

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function readCookie(req, name) {
  const raw = String(req.headers.cookie || '');
  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

function isAdmin(req) {
  const given = readCookie(req, COOKIE);
  if (!given || given.length !== adminCookie.length) return false;
  return crypto.timingSafeEqual(Buffer.from(given), Buffer.from(adminCookie));
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function emailKey(email) {
  return String(email || '').trim().toLowerCase();
}

function formatWhen(iso) {
  const date = new Date(iso || '');
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString();
}

function deviceKey(id) {
  const key = String(id || '').trim();
  return /^[a-zA-Z0-9_-]{8,80}$/.test(key) ? key : '';
}

function loadPresence() {
  let parsed = {};
  try {
    const raw = JSON.parse(fs.readFileSync(PRESENCE_PATH, 'utf8'));
    if (raw && typeof raw === 'object') parsed = raw;
  } catch {
    parsed = {};
  }
  const now = Date.now();
  const fresh = {};
  let dirty = false;
  for (const [key, device] of Object.entries(parsed)) {
    const id = deviceKey(device?.deviceId);
    const seen = Date.parse(device?.lastSeen || '');
    if (!id || id !== key || !Number.isFinite(seen) || now - seen > PRESENCE_KEEP_MS) {
      dirty = true;
      continue;
    }
    if (device.pending && !freshPending(device)) {
      device.pending = null;
      dirty = true;
    }
    if (device.command && !freshCommand(device)) {
      device.commandResult = expiredCommandResult(device);
      device.command = null;
      dirty = true;
    }
    if (device.commandResult && !freshCommandResult(device)) {
      device.commandResult = null;
      dirty = true;
    }
    fresh[key] = device;
  }
  if (dirty) savePresence(fresh);
  return fresh;
}

function savePresence(data) {
  fs.mkdirSync(path.dirname(PRESENCE_PATH), { recursive: true });
  fs.writeFileSync(PRESENCE_PATH, JSON.stringify(data, null, 2));
}

function loadAlerts() {
  try {
    const raw = JSON.parse(fs.readFileSync(ALERTS_PATH, 'utf8'));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

function saveAlerts(list) {
  fs.mkdirSync(path.dirname(ALERTS_PATH), { recursive: true });
  fs.writeFileSync(ALERTS_PATH, JSON.stringify(list));
}

function openAlerts() {
  const cutoff = Date.now() - 12 * 60 * 60 * 1000;
  return loadAlerts().filter((alert) => {
    if (alert?.dismissed) return false;
    const at = Date.parse(alert?.at || '');
    return Number.isFinite(at) && at >= cutoff;
  });
}

function rememberAlert(report, body) {
  if (report?.source !== 'alert') return;
  const list = loadAlerts();
  list.unshift({
    id: report.id,
    deviceId: deviceKey(body?.deviceId),
    email: report.email || '',
    hostname: report.hostname || '',
    message: String(report.message || '').slice(0, 300),
    at: report.createdAt,
    dismissed: false
  });
  saveAlerts(list.slice(0, 200));
}

/** One row per computer (or email), newest alert first, so a noisy device does not flood the list. */
function alertGroups(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const key = alert.deviceId || `email:${emailKey(alert.email)}`;
    if (!groups.has(key)) {
      groups.set(key, { key, deviceId: alert.deviceId || '', email: '', hostname: '', items: [] });
    }
    const group = groups.get(key);
    if (!group.email && alert.email) group.email = alert.email;
    if (!group.hostname && alert.hostname) group.hostname = alert.hostname;
    group.items.push(alert);
  }
  return [...groups.values()];
}

function alertMarkup(alerts) {
  if (!alerts.length) return '<p class="empty alert-empty">No open alerts.</p>';
  return `<ul class="alert-list">${alertGroups(alerts)
    .map((group) => {
      const latest = group.items[0];
      const who = group.email || 'No email';
      const href = group.deviceId ? `/device/${encodeURIComponent(group.deviceId)}` : '/';
      const ids = group.items.map((alert) => alert.id).join(',');
      const count = group.items.length > 1 ? `<span class="alert-chip">${group.items.length} alerts</span>` : '';
      const meta = [group.hostname, formatWhen(latest.at)].filter(Boolean).join(' · ');
      return `<li class="alert-item" data-alert-ids="${escapeHtml(ids)}">
        <div class="alert-main">
          <p class="alert-who"><strong>${escapeHtml(who)}</strong>${count}</p>
          <p class="alert-msg">${escapeHtml(latest.message || 'Alert')}</p>
          <p class="alert-meta">${escapeHtml(meta)}</p>
        </div>
        <div class="alert-actions">
          <a class="ghost small" href="${href}">Open</a>
          <button type="button" class="ghost small" data-dismiss-alert="${escapeHtml(ids)}" aria-label="Dismiss alerts for ${escapeHtml(who)}">Dismiss</button>
        </div>
      </li>`;
    })
    .join('')}</ul>`;
}

function dismissAlerts(ids, all) {
  const wanted = new Set((ids || []).map((id) => String(id)));
  const list = loadAlerts();
  let changed = false;
  for (const alert of list) {
    if (alert.dismissed) continue;
    if (all || wanted.has(String(alert.id))) {
      alert.dismissed = true;
      changed = true;
    }
  }
  if (changed) saveAlerts(list);
}

function alertPayload() {
  const alerts = openAlerts();
  return {
    alerts: alertMarkup(alerts),
    alertIds: alerts.map((alert) => alert.id),
    alertCount: alerts.length
  };
}

function isOnline(device) {
  if (!device?.lastSeen) return false;
  const seen = Date.parse(device.lastSeen);
  return Number.isFinite(seen) && Date.now() - seen <= ONLINE_MS;
}

function freshPending(device) {
  if (!device?.pending?.id || !device.pending.createdAt) return null;
  const created = Date.parse(device.pending.createdAt);
  if (!Number.isFinite(created) || Date.now() - created > REQUEST_MS) return null;
  return device.pending;
}

function freshCommand(device) {
  if (!device?.command?.id || !device.command.createdAt || !REMOTE_TYPES.has(device.command.type)) return null;
  const delivered = Date.parse(device.command.deliveredAt || '');
  if (Number.isFinite(delivered)) {
    return Date.now() - delivered > COMMAND_RUN_MS ? null : device.command;
  }
  const created = Date.parse(device.command.createdAt);
  if (!Number.isFinite(created) || Date.now() - created > REQUEST_MS) return null;
  return device.command;
}

/** A command that ran out of time without an answer becomes an error the admin can see. */
function expiredCommandResult(device) {
  const command = device?.command;
  if (!command?.id || !REMOTE_TYPES.has(command.type) || freshCommand(device)) return null;
  return {
    id: command.id,
    type: command.type,
    status: 'error',
    error: command.deliveredAt
      ? 'The app took the action but never said it finished.'
      : 'The app never picked it up. Make sure this computer runs the latest Dat Desk.',
    at: new Date().toISOString()
  };
}

function freshCommandResult(device) {
  const result = device?.commandResult;
  if (!result?.at || !REMOTE_TYPES.has(result.type)) return null;
  const at = Date.parse(result.at);
  if (!Number.isFinite(at) || Date.now() - at > 2 * 60 * 1000) return null;
  return result;
}

function remoteVerb(type) {
  return REMOTE_ACTIONS.find((action) => action.type === type)?.verb || 'run that action';
}

function listReports() {
  if (!fs.existsSync(DATA_DIR)) return [];
  const reports = [];
  for (const id of fs.readdirSync(DATA_DIR)) {
    const file = path.join(DATA_DIR, id, 'report.json');
    if (!fs.existsSync(file)) continue;
    try {
      reports.push(JSON.parse(fs.readFileSync(file, 'utf8')));
    } catch {
      // skip a broken folder
    }
  }
  reports.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return reports;
}

function collectBoxes(reports, presence) {
  const boxes = new Map();
  function ensure(key, email) {
    if (!boxes.has(key)) {
      boxes.set(key, { key, email: String(email || '').trim(), reports: [], devices: [] });
    }
    const box = boxes.get(key);
    if (!box.email && email) box.email = String(email).trim();
    return box;
  }
  for (const report of reports) {
    ensure(emailKey(report.email), report.email).reports.push(report);
  }
  for (const device of Object.values(presence)) {
    if (!device?.deviceId) continue;
    ensure(emailKey(device.email), device.email).devices.push(device);
  }
  return [...boxes.values()].sort((a, b) => {
    const aTime = a.reports[0]?.createdAt || a.devices[0]?.lastSeen || '';
    const bTime = b.reports[0]?.createdAt || b.devices[0]?.lastSeen || '';
    return String(bTime).localeCompare(String(aTime));
  });
}

function liveDevices(presence) {
  return Object.values(presence)
    .filter((device) => device?.deviceId && isOnline(device))
    .sort((a, b) => {
      if (a.loggedIn !== b.loggedIn) return a.loggedIn ? -1 : 1;
      return String(b.lastSeen).localeCompare(String(a.lastSeen));
    });
}

function flattenShots(reports) {
  const shots = [];
  for (const report of reports) {
    const files = Array.isArray(report.files) ? report.files : [];
    const when = formatWhen(report.createdAt) || '';
    const from = report.source === 'alert'
      ? 'Code editor detected'
      : report.source === 'admin'
        ? 'Requested by support'
        : 'Sent from Dat Desk';
    files.forEach((file, index) => {
      const screen = files.length > 1 ? ` · Screen ${index + 1}` : '';
      shots.push({
        src: `/reports/${encodeURIComponent(report.id)}/files/${encodeURIComponent(file)}`,
        caption: [when, from + screen].filter(Boolean).join(' · ')
      });
    });
  }
  return shots;
}

function platformLabel(platform) {
  const value = String(platform || '');
  if (value.startsWith('win')) return 'Windows';
  if (value.startsWith('darwin')) return 'Mac';
  if (value.startsWith('linux')) return 'Linux';
  return value.slice(0, 40);
}

function seenLabel(iso) {
  const seen = Date.parse(iso || '');
  if (!Number.isFinite(seen)) return '';
  const seconds = Math.max(0, Math.round((Date.now() - seen) / 1000));
  if (seconds < 10) return 'Just now';
  if (seconds < 60) return `${seconds}s ago`;
  return formatWhen(iso);
}

function viewToken(key) {
  return encodeURIComponent(key || '__none__');
}

function jsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function layout(title, body, options = {}) {
  const refreshSeconds = Number(options.refreshSeconds) || 0;
  const galleries = options.galleries;
  const subtitle = options.subtitle || 'Dat Desk screens';
  const alertList = options.board ? options.alerts || [] : null;
  const alertCount = alertList ? alertList.length : 0;
  const alertControl = alertList
    ? `<button type="button" id="alert-toggle" class="alert-toggle${alertCount ? ' has-alerts' : ''}" aria-expanded="false" aria-controls="alert-panel" aria-label="${alertCount === 1 ? '1 open alert' : `${alertCount} open alerts`}">
        <span class="alert-dot" aria-hidden="true"></span>Alerts <span id="alert-count" class="alert-badge">${alertCount}</span>
      </button>`
    : '';
  const alertPanel = alertList
    ? `<section id="alert-panel" class="alert-panel" aria-labelledby="alert-heading" hidden>
        <div class="alert-panel-head">
          <h2 id="alert-heading">Open alerts</h2>
          <button type="button" id="alert-dismiss-all" class="ghost small"${alertCount ? '' : ' disabled'}>Dismiss all</button>
          <button type="button" id="alert-close" class="ghost small">Close</button>
        </div>
        <div id="alert-slot" class="alert-scroll">${alertMarkup(alertList)}</div>
      </section>`
    : '';
  const viewer = galleries
    ? `<div class="viewer" id="viewer" hidden role="dialog" aria-modal="true" aria-labelledby="viewer-caption">
        <div class="viewer-bar">
          <p id="viewer-count"></p>
          <p id="viewer-caption"></p>
          <button type="button" id="viewer-close">Close</button>
        </div>
        <div class="viewer-stage">
          <button type="button" id="viewer-prev">Previous</button>
          <img id="viewer-img" alt="" />
          <button type="button" id="viewer-next">Next</button>
        </div>
        <p class="viewer-hint">Arrow keys move between screenshots. Escape closes this view.</p>
      </div>
      <script>
      (function () {
        const galleries = ${jsonForScript(galleries)};
        const viewer = document.getElementById('viewer');
        const img = document.getElementById('viewer-img');
        const caption = document.getElementById('viewer-caption');
        const count = document.getElementById('viewer-count');
        const prev = document.getElementById('viewer-prev');
        const next = document.getElementById('viewer-next');
        const closeBtn = document.getElementById('viewer-close');
        const main = document.getElementById('content');
        let galleryId = '';
        let index = 0;
        let lastFocus = null;
        function list() { return galleries[galleryId] || []; }
        function render() {
          const shot = list()[index];
          if (!shot) return;
          img.src = shot.src;
          img.alt = shot.caption || 'Screenshot';
          caption.textContent = shot.caption || 'Screenshot';
          count.textContent = (index + 1) + ' of ' + list().length;
          const single = list().length < 2;
          prev.disabled = single;
          next.disabled = single;
        }
        function openViewer(id, start) {
          galleryId = id;
          if (!list().length) return;
          index = ((start % list().length) + list().length) % list().length;
          lastFocus = document.activeElement;
          render();
          viewer.hidden = false;
          document.body.classList.add('viewer-open');
          if (main) main.setAttribute('aria-hidden', 'true');
          closeBtn.focus();
        }
        function closeViewer() {
          viewer.hidden = true;
          document.body.classList.remove('viewer-open');
          if (main) main.removeAttribute('aria-hidden');
          img.removeAttribute('src');
          if (lastFocus && lastFocus.focus) lastFocus.focus();
        }
        function step(delta) {
          if (list().length < 2) return;
          index = (index + delta + list().length) % list().length;
          render();
        }
        document.addEventListener('click', function (event) {
          const button = event.target.closest('[data-gallery]');
          if (!button) return;
          openViewer(button.getAttribute('data-gallery'), Number(button.getAttribute('data-index') || 0));
        });
        prev.addEventListener('click', function () { step(-1); });
        next.addEventListener('click', function () { step(1); });
        closeBtn.addEventListener('click', closeViewer);
        viewer.addEventListener('click', function (event) {
          if (event.target === viewer || event.target.classList.contains('viewer-stage')) closeViewer();
        });
        document.addEventListener('keydown', function (event) {
          if (viewer.hidden) return;
          if (event.key === 'Escape') { event.preventDefault(); closeViewer(); return; }
          if (event.key === 'ArrowLeft') { event.preventDefault(); step(-1); return; }
          if (event.key === 'ArrowRight') { event.preventDefault(); step(1); return; }
          if (event.key !== 'Tab') return;
          const items = [prev, next, closeBtn].filter(function (el) { return !el.disabled; });
          const first = items[0];
          const last = items[items.length - 1];
          if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        });
        const refresh = ${refreshSeconds};
        if (refresh > 0) {
          setInterval(function () {
            if (!viewer.hidden) return;
            location.reload();
          }, refresh * 1000);
        }
        const board = ${options.board ? 'true' : 'false'};
        function replaceGalleries(next) {
          Object.keys(galleries).forEach(function (key) { delete galleries[key]; });
          if (next) Object.assign(galleries, next);
        }
        if (board) {
          let inboxSignature = '';
          const seenAlerts = {};
          let alertsReady = false;
          let alertAudio = null;
          function playAlert() {
            try {
              const Context = window.AudioContext || window.webkitAudioContext;
              if (!Context) return;
              if (!alertAudio) alertAudio = new Context();
              if (alertAudio.state === 'suspended') alertAudio.resume();
              const now = alertAudio.currentTime;
              const gain = alertAudio.createGain();
              gain.connect(alertAudio.destination);
              gain.gain.setValueAtTime(0.0001, now);
              gain.gain.exponentialRampToValueAtTime(0.95, now + 0.02);
              gain.gain.setValueAtTime(0.95, now + 1.35);
              gain.gain.exponentialRampToValueAtTime(0.0001, now + 1.7);
              for (let step = 0; step < 8; step += 1) {
                const tone = alertAudio.createOscillator();
                tone.type = 'square';
                tone.frequency.value = step % 2 === 0 ? 880 : 520;
                tone.connect(gain);
                const start = now + step * 0.18;
                tone.start(start);
                tone.stop(start + 0.14);
              }
            } catch (err) {}
          }
          document.addEventListener('pointerdown', function () {
            if (alertAudio && alertAudio.state === 'suspended') alertAudio.resume();
          });
          const alertToggle = document.getElementById('alert-toggle');
          const alertPanel = document.getElementById('alert-panel');
          const alertSlot = document.getElementById('alert-slot');
          const alertCount = document.getElementById('alert-count');
          const alertClose = document.getElementById('alert-close');
          const alertAll = document.getElementById('alert-dismiss-all');
          // Ids dismissed here but maybe still in an answer that was already on its way.
          const dismissing = {};
          let alertHtml = alertSlot ? alertSlot.innerHTML : '';

          function setAlertCount(count) {
            if (alertCount) alertCount.textContent = String(count);
            if (alertToggle) {
              alertToggle.classList.toggle('has-alerts', count > 0);
              alertToggle.setAttribute('aria-label', count === 1 ? '1 open alert' : count + ' open alerts');
            }
            if (alertAll) alertAll.disabled = count === 0;
          }
          function openAlertPanel() {
            if (!alertPanel) return;
            alertPanel.hidden = false;
            if (alertToggle) alertToggle.setAttribute('aria-expanded', 'true');
          }
          function closeAlertPanel(returnFocus) {
            if (!alertPanel || alertPanel.hidden) return;
            alertPanel.hidden = true;
            if (alertToggle) {
              alertToggle.setAttribute('aria-expanded', 'false');
              if (returnFocus) alertToggle.focus();
            }
          }
          function countShown() {
            if (!alertSlot) return 0;
            let total = 0;
            alertSlot.querySelectorAll('[data-alert-ids]').forEach(function (row) {
              total += row.getAttribute('data-alert-ids').split(',').filter(Boolean).length;
            });
            return total;
          }
          function showEmptyIfNone() {
            if (alertSlot && !alertSlot.querySelector('[data-alert-ids]')) {
              alertSlot.innerHTML = '<p class="empty alert-empty">No open alerts.</p>';
            }
          }
          function sendDismiss(body) {
            return fetch('/alerts/dismiss', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify(body)
            }).then(function (response) { return response.ok ? response.json() : null; }).catch(function () { return null; });
          }
          if (alertToggle) {
            alertToggle.addEventListener('click', function () {
              if (alertPanel && alertPanel.hidden) openAlertPanel();
              else closeAlertPanel(false);
            });
          }
          if (alertClose) alertClose.addEventListener('click', function () { closeAlertPanel(true); });
          if (alertAll) {
            alertAll.addEventListener('click', function () {
              if (!alertSlot) return;
              alertSlot.querySelectorAll('[data-alert-ids]').forEach(function (row) {
                row.getAttribute('data-alert-ids').split(',').forEach(function (id) { if (id) dismissing[id] = true; });
              });
              alertSlot.innerHTML = '<p class="empty alert-empty">No open alerts.</p>';
              alertHtml = '';
              setAlertCount(0);
              sendDismiss({ all: true });
            });
          }
          document.addEventListener('click', function (event) {
            const button = event.target.closest('[data-dismiss-alert]');
            if (button) {
              const ids = button.getAttribute('data-dismiss-alert').split(',').filter(Boolean);
              ids.forEach(function (id) { dismissing[id] = true; });
              const row = button.closest('[data-alert-ids]');
              if (row) row.remove();
              showEmptyIfNone();
              alertHtml = '';
              setAlertCount(countShown());
              sendDismiss({ ids: ids });
              return;
            }
            if (alertPanel && !alertPanel.hidden && !event.target.closest('#alert-panel') && !event.target.closest('#alert-toggle')) {
              closeAlertPanel(false);
            }
          });
          document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' && alertPanel && !alertPanel.hidden && viewer.hidden) closeAlertPanel(true);
          });

          function applyAlerts(data) {
            const ids = Array.isArray(data.alertIds) ? data.alertIds : [];
            // Skip one round if the server still lists something we just dismissed.
            const stale = ids.some(function (id) { return dismissing[id]; });
            Object.keys(dismissing).forEach(function (id) { if (ids.indexOf(id) === -1) delete dismissing[id]; });
            let fresh = false;
            ids.forEach(function (id) {
              if (alertsReady && !seenAlerts[id]) fresh = true;
              seenAlerts[id] = true;
            });
            alertsReady = true;
            if (stale) return;
            if (alertSlot && data.alerts != null && data.alerts !== alertHtml) {
              const scroll = alertSlot.scrollTop;
              alertSlot.innerHTML = data.alerts;
              alertSlot.scrollTop = scroll;
              alertHtml = data.alerts;
            }
            setAlertCount(ids.length);
            if (fresh) {
              playAlert();
              openAlertPanel();
              if (alertToggle) {
                alertToggle.classList.remove('flash');
                void alertToggle.offsetWidth;
                alertToggle.classList.add('flash');
              }
            }
          }

          // Home page search and status filters; re-applied after every refresh.
          function applyHomeFilters() {
            const liveText = (document.getElementById('live-filter') || {}).value || '';
            const emailText = (document.getElementById('email-filter') || {}).value || '';
            const emailKind = (document.getElementById('email-kind') || {}).value || '';
            let liveShown = 0;
            document.querySelectorAll('#live-slot [data-search]').forEach(function (card) {
              const show = card.getAttribute('data-search').indexOf(liveText.trim().toLowerCase()) !== -1;
              card.hidden = !show;
              if (show) liveShown += 1;
            });
            let emailShown = 0;
            document.querySelectorAll('#people-slot [data-search]').forEach(function (row) {
              let show = row.getAttribute('data-search').indexOf(emailText.trim().toLowerCase()) !== -1;
              if (show && emailKind === 'live') show = row.getAttribute('data-live') === 'true';
              if (show && emailKind === 'alert') show = row.getAttribute('data-alert') === 'true';
              row.hidden = !show;
              if (show) emailShown += 1;
            });
            const liveNone = document.getElementById('live-none');
            if (liveNone) liveNone.hidden = !liveText.trim() || liveShown > 0;
            const emailNone = document.getElementById('email-none');
            if (emailNone) emailNone.hidden = (!emailText.trim() && !emailKind) || emailShown > 0;
          }
          ['live-filter', 'email-filter', 'email-kind'].forEach(function (id) {
            const field = document.getElementById(id);
            if (!field) return;
            field.addEventListener('input', applyHomeFilters);
            field.addEventListener('change', applyHomeFilters);
          });
          applyHomeFilters();
          (function () {
            const initialIds = ${jsonForScript(options.alertIds || [])};
            initialIds.forEach(function (id) { seenAlerts[id] = true; });
            alertsReady = true;
          })();

          setInterval(function () {
            fetch('/fragment/board').then(function (response) {
              if (!response.ok) return null;
              return response.json();
            }).then(function (data) {
              if (!data) return;
              const liveSlot = document.getElementById('live-slot');
              const liveCount = document.getElementById('live-count');
              if (liveSlot && data.live != null && liveSlot.innerHTML !== data.live) liveSlot.innerHTML = data.live;
              if (liveCount) liveCount.textContent = data.liveCount + ' open';
              const headerNote = document.getElementById('header-live');
              if (headerNote) headerNote.textContent = data.liveCount + ' live';
              applyAlerts(data);
              const peopleSlot = document.getElementById('people-slot');
              if (peopleSlot && data.people != null && data.peopleSignature !== inboxSignature) {
                inboxSignature = data.peopleSignature;
                peopleSlot.innerHTML = data.people;
              }
              applyHomeFilters();
            }).catch(function () {});
          }, 2000);
        }
        const streamDevice = ${jsonForScript(String(options.streamDevice || ''))};
        const personKey = ${jsonForScript(String(options.personKey || ''))};
        if (streamDevice) {
          const note = document.getElementById('live-note');
          const stage = document.getElementById('live-screens');
          const tools = document.getElementById('device-tools');
          const shotSlot = document.getElementById('shot-slot');
          const activitySlot = document.getElementById('activity-slot');
          const showBtn = document.getElementById('show-live');
          const stopBtn = document.getElementById('stop-live');
          const fullBtn = document.getElementById('full-live');
          const fps = document.getElementById('live-fps');
          const liveStage = document.getElementById('live-stage');
          const cover = document.getElementById('live-cover');
          const status = document.getElementById('live-status');
          let lastTools = '';
          let lastShots = '';
          let lastActivity = '';
          let allowed = showBtn ? !showBtn.disabled : false;
          let pickedScreens = [];
          let pickedIndex = 0;

          function hidePicker() {
            const picker = document.getElementById('live-picker');
            if (!picker) return;
            picker.hidden = true;
            picker.replaceChildren();
          }

          function renderPicker(screens, active) {
            const picker = document.getElementById('live-picker');
            if (!picker) return;
            if (!screens || screens.length < 2) {
              hidePicker();
              return;
            }
            picker.hidden = false;
            picker.replaceChildren();
            screens.forEach(function (screen, index) {
              const button = document.createElement('button');
              button.type = 'button';
              button.className = 'screen-pick';
              button.setAttribute('aria-pressed', index === active ? 'true' : 'false');
              button.textContent = screen.name || ('Screen ' + (index + 1));
              button.addEventListener('click', function () {
                if (index === pickedIndex) return;
                pickedIndex = index;
                renderPicker(screens, index);
                fetch('/api/webrtc/' + encodeURIComponent(streamDevice) + '/screen', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ index: index })
                }).catch(function () {});
              });
              picker.appendChild(button);
            });
          }
          let pc = null;
          let watching = false;
          let generation = 0;
          let pollTimer = 0;
          let fpsTimer = 0;

          function setNote(text) {
            if (note) note.textContent = text;
            if (status) {
              status.textContent = text;
              status.hidden = !watching;
            }
          }

          function setButtons() {
            if (showBtn) showBtn.disabled = !allowed || watching;
            if (stopBtn) stopBtn.hidden = !watching;
            if (fullBtn) fullBtn.hidden = !watching;
            if (cover) cover.hidden = watching;
          }

          function stopPeer() {
            watching = false;
            clearInterval(pollTimer);
            clearInterval(fpsTimer);
            pollTimer = 0;
            fpsTimer = 0;
            if (pc) {
              pc.getReceivers().forEach(function (receiver) {
                if (receiver.track) receiver.track.stop();
              });
              pc.close();
              pc = null;
            }
            if (stage) stage.replaceChildren();
            if (fps) fps.textContent = '';
            hidePicker();
            setButtons();
          }

          function formBody(extra) {
            return 'deviceId=' + encodeURIComponent(streamDevice) + (extra || '');
          }

          function deviceQuery() {
            const form = document.getElementById('activity-filters');
            if (!form) return '';
            const data = new URLSearchParams(new FormData(form));
            const text = data.toString();
            return text ? '?' + text : '';
          }

          function tickDevice() {
            fetch('/fragment/device/' + encodeURIComponent(streamDevice) + deviceQuery()).then(function (response) {
              if (!response.ok) return null;
              return response.json();
            }).then(function (part) {
              if (!part) return;
              const typing = tools && (tools.contains(document.activeElement) ||
                Array.prototype.some.call(tools.querySelectorAll('input[type="password"]'), function (field) { return field.value; }));
              if (tools && part.tools && part.tools !== lastTools && !typing) {
                lastTools = part.tools;
                tools.innerHTML = part.tools;
              }
              if (viewer.hidden && shotSlot && part.shots != null && part.shots !== lastShots) {
                lastShots = part.shots;
                shotSlot.innerHTML = part.shots;
                if (part.galleries) replaceGalleries(part.galleries);
              }
              if (activitySlot && part.activity != null && part.activity !== lastActivity) {
                lastActivity = part.activity;
                activitySlot.innerHTML = part.activity;
              }
              allowed = part.allowLive === true && part.online === true;
              if (!allowed && watching) {
                fetch('/watch/stop', {
                  method: 'POST',
                  headers: { 'content-type': 'application/x-www-form-urlencoded' },
                  body: formBody()
                }).catch(function () {});
                stopPeer();
              }
              if (!watching) {
                setNote(part.online !== true
                  ? 'This Dat Desk is not open.'
                  : allowed
                    ? 'The screen is covered.'
                    : 'Live view is off. Turn on Allow live in Dat Desk.');
              }
              setButtons();
            }).catch(function () {});
          }

          function waitIce(connection) {
            if (connection.iceGatheringState === 'complete') return Promise.resolve();
            return new Promise(function (resolve) {
              const done = function () {
                if (connection.iceGatheringState !== 'complete') return;
                connection.removeEventListener('icegatheringstatechange', done);
                resolve();
              };
              connection.addEventListener('icegatheringstatechange', done);
              setTimeout(resolve, 2000);
            });
          }

          async function showLive() {
            if (!allowed || watching) return;
            watching = true;
            setButtons();
            setNote('Asking Dat Desk to start.');
            if (stage) stage.replaceChildren();
            const started = await fetch('/watch', {
              method: 'POST',
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body: formBody()
            }).then(function (response) { return response.json(); });
            if (!started || !started.ok) {
              watching = false;
              setButtons();
              setNote(started && started.reason === 'denied'
                ? 'This person has not allowed live view.'
                : 'This Dat Desk is not open right now.');
              return;
            }
            generation = started.generation;
            pc = new RTCPeerConnection({ iceServers: [] });
            pc.ontrack = function (event) {
              const video = document.createElement('video');
              video.autoplay = true;
              video.playsInline = true;
              video.muted = true;
              video.srcObject = event.streams[0] || new MediaStream([event.track]);
              video.addEventListener('dblclick', function () {
                if (video.requestFullscreen) video.requestFullscreen();
              });
              if (stage) {
                stage.replaceChildren();
                stage.appendChild(video);
              }
              video.play().catch(function () {});
              if (status) status.hidden = true;
              if (note) {
                note.textContent = pickedScreens.length > 1
                  ? 'Watching one screen. Switch below to see another.'
                  : 'Watching this screen.';
              }
            };
            const deadline = Date.now() + 20000;
            let offer = '';
            while (watching && Date.now() < deadline && !offer) {
              const signal = await fetch('/api/webrtc/' + encodeURIComponent(streamDevice)).then(function (response) {
                return response.json();
              });
              if (signal && signal.generation === generation && signal.offer) {
                offer = signal.offer;
                pickedScreens = Array.isArray(signal.screens) ? signal.screens : [];
                pickedIndex = Number(signal.screenIndex) || 0;
                renderPicker(pickedScreens, pickedIndex);
              } else await new Promise(function (resolve) { setTimeout(resolve, 300); });
            }
            if (!watching) return;
            if (!offer || !pc) {
              await fetch('/watch/stop', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: formBody()
              }).catch(function () {});
              stopPeer();
              setNote('Dat Desk did not start the live view. Leave the app open, with Allow live checked, and try again.');
              return;
            }
            await pc.setRemoteDescription({ type: 'offer', sdp: offer });
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            await waitIce(pc);
            await fetch('/api/webrtc/' + encodeURIComponent(streamDevice), {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ generation: generation, answer: pc.localDescription.sdp })
            });
            fpsTimer = setInterval(function () {
              if (!pc) return;
              pc.getStats().then(function (stats) {
                stats.forEach(function (report) {
                  if (report.type === 'inbound-rtp' && report.kind === 'video' && report.framesPerSecond) {
                    if (fps) fps.textContent = Math.round(report.framesPerSecond) + ' fps';
                  }
                });
              }).catch(function () {});
            }, 1000);
          }

          if (showBtn) showBtn.addEventListener('click', function () { showLive().catch(function () { stopPeer(); }); });
          if (stopBtn) stopBtn.addEventListener('click', function () {
            fetch('/watch/stop', {
              method: 'POST',
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body: formBody()
            }).catch(function () {});
            stopPeer();
            if (allowed) setNote('Live view stopped. The screen is covered.');
          });
          if (fullBtn) fullBtn.addEventListener('click', function () {
            if (!liveStage) return;
            if (document.fullscreenElement) document.exitFullscreen();
            else liveStage.requestFullscreen();
          });
          const activityFiltersForm = document.getElementById('activity-filters');
          if (activityFiltersForm) {
            activityFiltersForm.addEventListener('submit', function (event) { event.preventDefault(); });
            activityFiltersForm.addEventListener('change', function () {
              lastActivity = '';
              tickDevice();
            });
          }
          setButtons();
          tickDevice();
          setInterval(tickDevice, 2000);
        }
        if (personKey && !streamDevice) {
          const personActivity = document.getElementById('activity-slot');
          const personShots = document.getElementById('shot-slot');
          let personActivityHtml = '';
          let personShotHtml = '';
          function personQuery() {
            const form = document.getElementById('activity-filters');
            if (!form) return '';
            const data = new URLSearchParams(new FormData(form));
            const text = data.toString();
            return text ? '?' + text : '';
          }
          function tickPerson() {
            fetch('/fragment/user/' + encodeURIComponent(personKey) + personQuery()).then(function (response) {
              return response.ok ? response.json() : null;
            }).then(function (part) {
              if (!part) return;
              if (viewer.hidden && personShots && part.shots != null && part.shots !== personShotHtml) {
                personShotHtml = part.shots;
                personShots.innerHTML = part.shots;
                if (part.galleries) replaceGalleries(part.galleries);
              }
              if (personActivity && part.activity != null && part.activity !== personActivityHtml) {
                personActivityHtml = part.activity;
                personActivity.innerHTML = part.activity;
              }
            }).catch(function () {});
          }
          const personFilters = document.getElementById('activity-filters');
          if (personFilters) {
            personFilters.addEventListener('submit', function (event) { event.preventDefault(); });
            personFilters.addEventListener('change', function () {
              personActivityHtml = '';
              tickPerson();
            });
          }
          tickPerson();
          setInterval(tickPerson, 4000);
        }
        const params = new URLSearchParams(location.search);
        const start = Number(params.get('shot'));
        if (params.has('shot') && galleries.view && galleries.view[start]) {
          params.delete('shot');
          const query = params.toString();
          history.replaceState(null, '', location.pathname + (query ? '?' + query : ''));
          openViewer('view', start);
        }
      })();
      </script>`
    : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #e7ebf0;
      --surface: #ffffff;
      --ink: #1a1d23;
      --muted: #4b5563;
      --line: #d5dbe3;
      --accent: #0f3d75;
      --header: #161b22;
      --ok: #05603a;
      --warn: #9a3412;
      --stage: #121417;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font: 15px/1.45 "Segoe UI", system-ui, sans-serif; background: var(--bg); color: var(--ink); }
    body.viewer-open { overflow: hidden; }
    :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .skip { position: absolute; left: 8px; top: -48px; background: #fff; color: var(--header); padding: 8px 12px; z-index: 40; }
    .skip:focus { top: 8px; }
    header { display: flex; align-items: center; gap: 16px; height: 56px; padding: 0 24px; background: var(--header); color: #fff; position: sticky; top: 0; z-index: 20; }
    .brand { color: #fff; font-weight: 700; text-decoration: none; font-size: 16px; letter-spacing: 0.01em; }
    .header-note { margin: 0 0 0 auto; color: #d0d7de; font-size: 14px; }
    main { margin: 0 auto; padding: 16px 24px 24px; }
    h1, h2, h3 { margin: 0; overflow-wrap: anywhere; line-height: 1.25; }
    h1 { font-size: 20px; }
    h2 { font-size: 16px; }
    h3 { font-size: 14px; }
    a { color: var(--accent); }
    .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
    .section-head p, .meta, .empty { color: var(--muted); }
    .meta { font-size: 14px; margin: 0; }
    .empty { margin: 0; }
    .home-split { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 380px); gap: 16px; align-items: start; }
    .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 16px; min-width: 0; }
    .card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
    a.live-card, a.email-row {
      display: flex; flex-direction: column; gap: 4px; color: inherit; text-decoration: none;
      background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    }
    a.live-card:hover, a.email-row:hover { border-color: #8ea0b5; }
    a.live-card strong, a.email-row strong { font-size: 14px; color: var(--ink); }
    a.live-card span, a.email-row span { color: var(--muted); font-size: 12px; line-height: 1.4; }
    a.live-card.is-alert, a.email-row.is-alert { border-color: #b42318; background: #fff8f7; }
    .email-list { display: flex; flex-direction: column; gap: 8px; }
    .email-top { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
    .email-top time { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; white-space: nowrap; }
    .marks { display: flex; flex-wrap: wrap; gap: 4px; }
    .mark { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; font-weight: 600; line-height: 1.3; padding: 2px 6px; border-radius: 4px; background: #eef1f4; color: #334155; }
    .mark.live { background: #e7f6ee; color: var(--ok); }
    .mark.alert { background: #fdecea; color: #7a271a; }
    .workspace-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; margin-bottom: 12px; }
    .workspace-head h1 { margin-right: auto; }
    .workspace-head .meta { margin: 0; }
    .device-split { display: grid; grid-template-columns: minmax(0, 7fr) minmax(260px, 3fr); gap: 16px; align-items: stretch; height: calc(100vh - 96px); min-height: 480px; }
    .live-pane { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    .live-bar { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-bottom: 1px solid var(--line); background: var(--surface); }
    .live-bar h2 { margin-right: auto; }
    #live-fps { margin: 0; color: var(--muted); font-size: 14px; font-variant-numeric: tabular-nums; min-height: 1.2em; }
    .live-frame { position: relative; flex: 1; min-height: 0; background: var(--stage); }
    .live-cover {
      position: absolute; inset: 0; z-index: 2; display: flex; flex-direction: column;
      align-items: center; justify-content: center; gap: 12px; padding: 24px; text-align: center; background: var(--stage);
    }
    .live-cover[hidden] { display: none; }
    .live-cover p { margin: 0; max-width: 36ch; color: #d5dbe3; }
    .live-cover button { background: #fff; color: var(--stage); min-width: 160px; min-height: 48px; font-weight: 700; }
    .live-cover button:disabled { background: #3d4450; color: #e8edf2; opacity: 1; }
    .live-status {
      position: absolute; z-index: 2; left: 16px; right: 16px; top: 16px; margin: 0;
      text-align: center; color: #d5dbe3;
    }
    .live-status[hidden] { display: none; }
    .live-picker {
      position: absolute; z-index: 3; left: 12px; right: 12px; bottom: 12px;
      display: flex; flex-wrap: wrap; gap: 8px;
    }
    .live-picker[hidden] { display: none; }
    .live-screens { position: absolute; inset: 0; }
    .live-screens video, .live-screens img {
      width: 100%; height: 100%; object-fit: contain; background: var(--stage); border: 0; border-radius: 0;
    }
    .side-pane { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    .tablist { display: flex; border-bottom: 1px solid var(--line); background: #f7f8fa; }
    .tablist button {
      flex: 1; background: transparent; color: var(--muted); border: 0; border-radius: 0;
      border-bottom: 2px solid transparent; min-height: 44px; font-weight: 600;
    }
    .tablist button[aria-selected="true"] { color: var(--ink); border-bottom-color: var(--accent); background: var(--surface); }
    .tab-panel { flex: 1; overflow: auto; padding: 12px; }
    .tab-panel[hidden] { display: none; }
    .mini-filters { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
    .mini-filters select {
      width: 100%; min-height: 40px; padding: 8px; border: 1px solid var(--line); border-radius: 8px;
      background: #fff; color: var(--ink); font: inherit;
    }
    .pills { display: flex; flex-wrap: wrap; gap: 8px; }
    .pill { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; line-height: 1.3; padding: 4px 8px; border-radius: 4px; background: #eef1f4; color: #334155; }
    .pill.live { background: #e7f6ee; color: var(--ok); }
    .pill.ok { background: #e7f6ee; color: var(--ok); }
    .pill.warn { background: #fff4e8; color: var(--warn); }
    .pill.stream { background: #e8f1fb; color: #0f3d75; }
    .pill.alert { background: #fdecea; color: #7a271a; }
    .alert-toggle {
      display: inline-flex; align-items: center; gap: 8px; min-height: 36px; padding: 6px 12px;
      background: #2a313b; color: #e6edf3; border: 1px solid #3d4652;
    }
    .alert-toggle:hover { background: #333c48; }
    .alert-toggle .alert-dot { width: 8px; height: 8px; border-radius: 50%; background: #6b7785; }
    .alert-toggle .alert-badge {
      min-width: 22px; padding: 0 6px; border-radius: 999px; background: #3d4652; color: #fff;
      font-size: 12px; font-weight: 700; line-height: 20px; text-align: center; font-variant-numeric: tabular-nums;
    }
    .alert-toggle.has-alerts { background: #7a1d14; border-color: #b42318; color: #fff; }
    .alert-toggle.has-alerts .alert-dot { background: #ffb4ab; }
    .alert-toggle.has-alerts .alert-badge { background: #fff; color: #7a1d14; }
    .alert-toggle.flash { animation: alert-flash 0.6s ease-in-out 3; }
    @keyframes alert-flash { 50% { background: #d92d20; } }
    .alert-panel {
      position: fixed; top: 64px; right: 16px; z-index: 25; width: min(460px, calc(100vw - 32px));
      max-height: calc(100vh - 80px); display: flex; flex-direction: column;
      background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
      box-shadow: 0 16px 40px rgba(15, 23, 42, 0.22);
    }
    .alert-panel[hidden] { display: none; }
    .alert-panel-head { display: flex; align-items: center; gap: 8px; padding: 12px 12px 12px 16px; border-bottom: 1px solid var(--line); }
    .alert-panel-head h2 { margin-right: auto; }
    .alert-scroll { overflow: auto; overscroll-behavior: contain; padding: 8px; }
    .alert-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
    .alert-item {
      display: flex; gap: 12px; align-items: flex-start; padding: 10px 12px;
      border: 1px solid #f5c2c0; border-left: 4px solid #b42318; border-radius: 8px; background: #fff8f7;
    }
    .alert-main { flex: 1; min-width: 0; }
    .alert-main p { margin: 0; }
    .alert-who { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; font-size: 14px; overflow-wrap: anywhere; }
    .alert-chip { font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 999px; background: #fdecea; color: #7a271a; border: 1px solid #f5c2c0; }
    .alert-msg { color: #7a271a; font-size: 13px; margin-top: 2px !important; overflow-wrap: anywhere; }
    .alert-meta { color: var(--muted); font-size: 12px; margin-top: 2px !important; }
    .alert-actions { display: flex; flex-direction: column; gap: 6px; }
    .alert-empty { padding: 16px; text-align: center; }
    .ghost.small, button.small { min-height: 32px; padding: 4px 10px; font-size: 13px; text-align: center; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }
    .filter-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 12px; }
    .filter-row input, .filter-row select {
      flex: 1; min-width: 140px; min-height: 38px; padding: 8px 10px; border: 1px solid var(--line);
      border-radius: 8px; background: #fff; color: var(--ink); font: inherit; font-size: 14px;
    }
    .filter-row select { flex: 0 0 auto; }
    [data-search][hidden] { display: none !important; }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    label { display: block; font-size: 14px; color: var(--muted); margin-bottom: 8px; }
    input, button, select { font: inherit; }
    input[type="password"] { width: 100%; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; background: #fff; color: var(--ink); }
    button, .ghost {
      background: var(--accent); color: #fff; border: 0; border-radius: 8px; padding: 8px 14px; min-height: 40px; cursor: pointer;
    }
    button:disabled { background: #3d4450; color: #e8edf2; cursor: default; }
    .ghost { background: #fff; color: var(--accent); border: 1px solid var(--line); }
    .ghost:disabled { background: #eef1f4; color: var(--muted); }
    form.card { max-width: 420px; margin: 48px auto; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    form.card h1 { margin-bottom: 8px; }
    form.card button { width: 100%; margin-top: 8px; }
    .inline-form { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 0; }
    .inline-form .meta { margin: 0; }
    .remote-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 0; }
    .remote-actions button { background: #fff; color: var(--ink); border: 1px solid var(--line); }
    .remote-actions button.danger { background: #fdecea; color: #7a271a; border-color: #f5c2c0; }
    .remote-actions button:disabled { background: #eef1f4; color: var(--muted); border-color: var(--line); }
    .remote-note { margin: 8px 0 0; }
    .signin-form { margin: 12px 0 0; padding: 12px; background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--accent); border-radius: 8px; }
    .signin-form h2 { font-size: 15px; }
    .signin-form .meta { margin: 4px 0 8px; font-size: 13px; }
    .signin-fields { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 8px; }
    .signin-fields label { display: flex; flex-direction: column; gap: 4px; margin: 0; font-size: 13px; flex: 1; min-width: 180px; }
    .signin-fields input {
      min-height: 40px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px;
      background: #fff; color: var(--ink); font: inherit;
    }
    .shots { display: grid; grid-template-columns: 1fr; gap: 8px; }
    button.thumb {
      display: block; width: 100%; padding: 0; background: var(--stage); border-radius: 8px; overflow: hidden; cursor: zoom-in; text-align: left;
    }
    button.thumb img { display: block; width: 100%; height: 120px; object-fit: contain; background: var(--stage); margin: 0; border: 0; }
    .thumb-cap { display: block; padding: 8px; background: #fff; color: #334155; font-size: 12px; line-height: 1.35; }
    .banner { background: #e8f1fb; border: 1px solid #c5d7ee; color: #0f3d75; border-radius: 8px; padding: 12px 16px; margin: 0 0 12px; }
    .stat-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 12px; }
    .stat-row p { margin: 0; background: #f7f8fa; border: 1px solid var(--line); border-radius: 8px; padding: 8px; font-size: 12px; }
    .last-recorded { display: flex; flex-direction: column; gap: 2px; margin: 0 0 12px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
    .last-recorded span { color: var(--muted); font-size: 12px; }
    .timeline { display: flex; flex-direction: column; gap: 8px; }
    .day-label { margin: 8px 0 0; color: var(--muted); font-size: 12px; font-weight: 600; }
    .event { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px; }
    .event strong { display: block; font-size: 14px; }
    .event .meta { margin: 2px 0 0; font-size: 12px; }
    .back { color: var(--accent); font-weight: 600; text-decoration: none; }
    .back:hover { text-decoration: underline; }
    .viewer {
      position: fixed; inset: 0; z-index: 30; background: #121417;
      display: flex; flex-direction: column; color: #f8fafc;
    }
    .viewer[hidden] { display: none; }
    .viewer-bar { display: flex; align-items: center; gap: 16px; padding: 12px 16px; }
    .viewer-bar p { margin: 0; }
    #viewer-count { font-variant-numeric: tabular-nums; color: #cbd5e1; white-space: nowrap; }
    #viewer-caption { flex: 1; }
    .viewer button { background: #1e293b; color: #f8fafc; border: 1px solid #64748b; min-width: 96px; }
    .viewer :focus-visible { outline-color: #fff; }
    .viewer-stage {
      flex: 1; min-height: 0; display: grid; grid-template-columns: auto minmax(0, 1fr) auto;
      align-items: center; gap: 12px; padding: 8px 16px;
    }
    .viewer-stage img {
      display: block; max-width: min(100%, 1400px); max-height: calc(100vh - 140px);
      width: auto; height: auto; margin: 0 auto; object-fit: contain; background: #020617; border-radius: 8px;
    }
    .viewer-hint { margin: 0; padding: 0 16px 16px; color: #cbd5e1; font-size: 14px; }
    button.screen-pick { background: #fff; color: var(--accent); border: 1px solid var(--line); }
    button.screen-pick[aria-pressed="true"] { background: var(--accent); color: #fff; border-color: var(--accent); }
    #live-stage:fullscreen { background: var(--stage); border-radius: 0; }
    #live-stage:fullscreen .live-frame { min-height: 0; }
    #live-stage:fullscreen .live-screens video,
    #live-stage:fullscreen .live-screens img { max-height: none; }
    .workspace-head #device-tools { flex-basis: 100%; }
    @media (max-width: 900px) {
      .home-split, .device-split { grid-template-columns: 1fr; }
      .device-split { height: auto; }
      .side-pane { max-height: 80vh; }
      .live-frame { min-height: 320px; }
      header { padding: 0 16px; }
      main { padding: 12px 16px 24px; }
      .alert-panel { top: 60px; right: 8px; width: calc(100vw - 16px); }
      .viewer-stage { grid-template-columns: 1fr; }
      .viewer-stage img { max-height: 58vh; }
    }
    @media (prefers-reduced-motion: reduce) {
      * { scroll-behavior: auto; }
    }
  </style>
</head>
<body class="${options.workspace ? 'workspace' : ''}">
  <a class="skip" href="#content">Skip to content</a>
  <header>
    <a class="brand" href="/">TrackingEye</a>
    <p class="header-note" id="header-live">${escapeHtml(subtitle)}</p>
    ${alertControl}
  </header>
  ${alertPanel}
  <main id="content">${body}</main>
  ${viewer}
</body>
</html>`;
}

function loginPage(error) {
  return layout(
    'TrackingEye',
    `<form class="card" method="post" action="/login">
      <h1>Open the inbox</h1>
      <p class="meta">Live apps and each email’s last recorded activity show up here.</p>
      ${error ? `<p class="warn">${escapeHtml(error)}</p>` : ''}
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Open inbox</button>
    </form>`
  );
}

function inboxNotice(value) {
  const notice = String(value || '');
  return ['waiting', 'offline', 'denied', 'queued', 'sent', 'busy', 'bad', 'signedin', 'missing'].includes(notice) ? notice : '';
}

function noticeBanner(notice, pending, reports) {
  const justCaptured = (reports || []).some((report) => {
    if (report.source !== 'admin') return false;
    const created = Date.parse(report.createdAt || '');
    return Number.isFinite(created) && Date.now() - created < REQUEST_MS;
  });
  if (notice === 'waiting' && pending) {
    return '<p class="banner" role="status">Waiting for Dat Desk to send the screen. This page refreshes on its own.</p>';
  }
  if (notice === 'waiting' && !justCaptured) {
    return '<p class="banner" role="status">Dat Desk did not send a screenshot. The app needs to stay open, with Allow support to capture checked.</p>';
  }
  if (notice === 'offline') return '<p class="banner" role="status">That Dat Desk app is not open right now.</p>';
  if (notice === 'denied') {
    return '<p class="banner" role="status">This person has not allowed support to capture the screen.</p>';
  }
  if (notice === 'queued') return '<p class="banner" role="status">A capture request is already waiting.</p>';
  if (notice === 'sent') {
    return '<p class="banner" role="status">Sent. This Dat Desk will do it the next time it checks in.</p>';
  }
  if (notice === 'busy') {
    return '<p class="banner" role="status">This Dat Desk is already doing a remote action. Wait for it to finish.</p>';
  }
  if (notice === 'bad') return '<p class="banner" role="status">That action is not available.</p>';
  if (notice === 'signedin') {
    return '<p class="banner" role="status">This Dat Desk is already signed in. Sign it out first.</p>';
  }
  if (notice === 'missing') return '<p class="banner" role="status">Enter both the email and the password.</p>';
  return '';
}

function captureForm(device, returnTo) {
  if (!isOnline(device)) return '';
  const where = escapeHtml(device.hostname || 'This computer');
  const state = device.loggedIn ? 'Signed in' : 'On the sign-in screen';
  if (device.allowRemote !== true) {
    return `<p class="meta warn">${where} is open (${state}). Capture is turned off on this Dat Desk.</p>`;
  }
  if (freshPending(device)) {
    return `<p class="meta">${where} is sending a screenshot.</p>`;
  }
  const back = returnTo === 'device' ? '<input type="hidden" name="returnTo" value="device" />' : '';
  return `<form method="post" action="/capture-requests" class="inline-form">
    <input type="hidden" name="deviceId" value="${escapeHtml(device.deviceId)}" />
    ${back}
    <button type="submit">Get screenshot</button>
    <span class="meta">${where} · ${state}</span>
  </form>`;
}

function deviceCards(devices, alertIds) {
  const flagged = alertIds instanceof Set ? alertIds : new Set(alertIds || []);
  if (!devices.length) {
    return '<p class="empty">No Dat Desk app is open.</p>';
  }
  const marks = new Map();
  for (const device of devices) {
    const mark = `${device.hostname}|${emailKey(device.email)}|${device.loggedIn === true}`;
    marks.set(mark, (marks.get(mark) || 0) + 1);
  }
  return `<div class="card-grid">${devices
    .map((device) => {
      const signedIn = device.loggedIn === true && Boolean(emailKey(device.email));
      const title = signedIn ? device.email : 'Not signed in';
      const mark = `${device.hostname}|${emailKey(device.email)}|${device.loggedIn === true}`;
      const host = device.hostname || 'This computer';
      const suffix = marks.get(mark) > 1 ? ` · ${String(device.deviceId).slice(-4)}` : '';
      const where = [host + suffix, platformLabel(device.platform)].filter(Boolean).join(' · ');
      const href = `/device/${encodeURIComponent(device.deviceId)}`;
      const alert = flagged.has(device.deviceId);
      const search = [device.email, host, platformLabel(device.platform)].join(' ').toLowerCase();
      return `<a class="live-card${alert ? ' is-alert' : ''}" href="${href}" data-search="${escapeHtml(search)}">
        <span class="marks">
          <span class="mark live">Live</span>
          ${signedIn ? '<span class="mark">Signed in</span>' : '<span class="mark">Sign-in screen</span>'}
          ${alert ? '<span class="mark alert">Alert</span>' : ''}
        </span>
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(where)}</span>
        <span>Seen ${escapeHtml(seenLabel(device.lastSeen))}</span>
      </a>`;
    })
    .join('')}</div>`;
}

function bestDevice(devices) {
  const list = (devices || []).filter((device) => device?.deviceId);
  list.sort((a, b) => {
    const aOn = isOnline(a) ? 1 : 0;
    const bOn = isOnline(b) ? 1 : 0;
    if (aOn !== bOn) return bOn - aOn;
    return String(b.lastSeen || '').localeCompare(String(a.lastSeen || ''));
  });
  return list[0] || null;
}

function personHref(key, devices) {
  const pick = bestDevice(devices);
  if (pick) return `/device/${encodeURIComponent(pick.deviceId)}`;
  return `/user/${viewToken(key)}`;
}

function lastRecorded(key, entries, reports) {
  const act = entries.find((entry) => (emailKey(entry.email) || '') === (key || ''));
  const report = reports.find((item) => emailKey(item.email) === (key || ''));
  const actAt = Date.parse(act?.at || '');
  const repAt = Date.parse(report?.createdAt || '');
  if (act && Number.isFinite(actAt) && (!report || !Number.isFinite(repAt) || actAt >= repAt)) {
    return { at: act.at, text: activityText(act) };
  }
  if (report && Number.isFinite(repAt)) {
    const text = report.source === 'alert'
      ? 'Alert screenshot'
      : report.source === 'admin'
        ? 'Screenshot requested'
        : 'Screenshot sent';
    return { at: report.createdAt, text };
  }
  return null;
}

function emailDirectory(reports, presence, entries, alerts) {
  const flaggedEmails = new Set();
  const flaggedDevices = new Set();
  for (const alert of alerts || []) {
    if (alert?.email) flaggedEmails.add(emailKey(alert.email));
    if (alert?.deviceId) flaggedDevices.add(alert.deviceId);
  }
  const map = new Map();
  function ensure(key, email) {
    const id = key || '';
    if (!map.has(id)) map.set(id, { key: id, email: String(email || '').trim(), devices: [] });
    const row = map.get(id);
    if (email && !row.email) row.email = String(email).trim();
    return row;
  }
  for (const report of reports) ensure(emailKey(report.email), report.email);
  for (const device of Object.values(presence || {})) {
    if (!device?.deviceId) continue;
    ensure(emailKey(device.email), device.email).devices.push(device);
  }
  for (const entry of entries || []) ensure(emailKey(entry.email), entry.email);
  const rows = [...map.values()].map((row) => ({
    ...row,
    recorded: lastRecorded(row.key, entries || [], reports),
    href: personHref(row.key, row.devices),
    online: row.devices.some(isOnline),
    alert: flaggedEmails.has(row.key) || row.devices.some((device) => flaggedDevices.has(device.deviceId))
  }));
  rows.sort((a, b) => {
    const aTime = a.recorded?.at || '';
    const bTime = b.recorded?.at || '';
    return String(bTime).localeCompare(String(aTime));
  });
  if (!rows.length) return '<p class="empty">No emails recorded yet.</p>';
  return `<div class="email-list">${rows
    .map((row) => {
      const label = row.email || 'No email';
      const when = row.recorded ? formatWhen(row.recorded.at) : 'No record yet';
      const what = row.recorded ? row.recorded.text : 'Nothing recorded';
      const marks = [
        row.online ? '<span class="mark live">Live</span>' : '',
        row.alert ? '<span class="mark alert">Alert</span>' : ''
      ].filter(Boolean).join('');
      const search = [label, ...row.devices.map((device) => device.hostname || '')].join(' ').toLowerCase();
      return `<a class="email-row${row.alert ? ' is-alert' : ''}" href="${row.href}" data-search="${escapeHtml(search)}" data-live="${row.online}" data-alert="${row.alert}">
        <span class="email-top"><strong>${escapeHtml(label)}</strong><time>${escapeHtml(when)}</time></span>
        ${marks ? `<span class="marks">${marks}</span>` : ''}
        <span>${escapeHtml(what)}</span>
      </a>`;
    })
    .join('')}</div>`;
}

function inboxHome(reports, presence, entries, notice) {
  const devices = liveDevices(presence);
  const alerts = openAlerts();
  const alertIds = new Set(alerts.map((alert) => alert.deviceId).filter(Boolean));
  return layout(
    'TrackingEye',
    `${noticeBanner(notice, false, reports)}
    <div class="home-split">
      <section class="panel" aria-labelledby="live-heading">
        <div class="section-head">
          <h1 id="live-heading">Live apps</h1>
          <p id="live-count">${devices.length} open</p>
        </div>
        <div class="filter-row">
          <input id="live-filter" type="search" placeholder="Search email or computer" aria-label="Search live apps" autocomplete="off" />
        </div>
        <p id="live-none" class="empty" hidden>No live app matches that search.</p>
        <div id="live-slot">${deviceCards(devices, alertIds)}</div>
      </section>
      <section class="panel" aria-labelledby="email-heading">
        <div class="section-head">
          <h2 id="email-heading">Emails</h2>
          <p>Last recorded</p>
        </div>
        <div class="filter-row">
          <input id="email-filter" type="search" placeholder="Search email" aria-label="Search emails" autocomplete="off" />
          <select id="email-kind" aria-label="Show">
            <option value="">All</option>
            <option value="live">Live now</option>
            <option value="alert">With alerts</option>
          </select>
        </div>
        <p id="email-none" class="empty" hidden>No email matches.</p>
        <div id="people-slot">${emailDirectory(reports, presence, entries, alerts)}</div>
      </section>
    </div>`,
    {
      galleries: {},
      board: true,
      alerts,
      alertIds: alerts.map((alert) => alert.id),
      subtitle: `${devices.length} live`
    }
  );
}

function activityFilterForm() {
  return `<form id="activity-filters" class="mini-filters">
      <select name="kind" aria-label="Activity type">
        <option value="">Everything</option>
        <option value="signin">Sign in and out</option>
        <option value="open">Open DAT</option>
        <option value="visit">Time in DAT</option>
        <option value="screen">Screenshots and alerts</option>
        <option value="settings">Capture and live</option>
      </select>
      <select name="range" aria-label="When">
        <option value="">All time</option>
        <option value="today">Today</option>
        <option value="7">Last 7 days</option>
        <option value="30">Last 30 days</option>
      </select>
    </form>`;
}

function workspaceTabs() {
  return `<script>
    (function () {
      var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-tab]'));
      function select(name) {
        tabs.forEach(function (tab) {
          var on = tab.getAttribute('data-tab') === name;
          tab.setAttribute('aria-selected', on ? 'true' : 'false');
          tab.tabIndex = on ? 0 : -1;
        });
        ['activity', 'shots'].forEach(function (key) {
          var panel = document.getElementById('panel-' + key);
          if (panel) panel.hidden = key !== name;
        });
      }
      tabs.forEach(function (tab, index) {
        tab.addEventListener('click', function () { select(tab.getAttribute('data-tab')); });
        tab.addEventListener('keydown', function (event) {
          if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
          event.preventDefault();
          var next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : (index - 1 + tabs.length) % tabs.length;
          tabs[next].focus();
          select(tabs[next].getAttribute('data-tab'));
        });
      });
    })();
    </script>`;
}

function workspacePage(options) {
  const device = options.device || null;
  const reports = options.reports || [];
  const entries = options.entries || [];
  const shots = flattenShots(reports);
  const pending = Boolean(device && freshPending(device));
  const online = Boolean(device && isOnline(device));
  const allowLive = device?.allowLive === true && online;
  const activity = activityPanel(entries, {
    email: options.email || device?.email || '',
    deviceId: device?.deviceId || ''
  });
  const note = !online
    ? 'This Dat Desk is not open.'
    : allowLive
      ? 'The screen is covered.'
      : 'Live view is off. Turn on Allow live in Dat Desk.';
  const alerts = openAlerts();
  return layout(
    options.title,
    `${noticeBanner(options.notice, pending, reports)}
    <div class="workspace-head">
      <a class="back" href="/">All apps</a>
      <h1>${escapeHtml(options.heading)}</h1>
      <p class="meta">${escapeHtml(options.sub || '')}</p>
      <div id="device-tools">${options.tools}</div>
    </div>
    <div class="device-split">
      <section class="live-pane" id="live-stage" aria-labelledby="stream-heading">
        <div class="live-bar">
          <h2 id="stream-heading">Live</h2>
          <p id="live-fps"></p>
          <button type="button" id="stop-live" hidden>Stop</button>
          <button type="button" id="full-live" hidden>Full screen</button>
        </div>
        <div class="live-frame">
          <div id="live-screens" class="live-screens"></div>
          <div id="live-cover" class="live-cover">
            <p id="live-note">${escapeHtml(note)}</p>
            <button type="button" id="show-live"${allowLive ? '' : ' disabled'}>Show live</button>
          </div>
          <p id="live-status" class="live-status" hidden></p>
          <div id="live-picker" class="live-picker" role="group" aria-label="Screens" hidden></div>
        </div>
      </section>
      <aside class="side-pane">
        <div class="tablist" role="tablist" aria-label="This user">
          <button type="button" id="tab-activity" role="tab" data-tab="activity" aria-selected="true" aria-controls="panel-activity">Activity</button>
          <button type="button" id="tab-shots" role="tab" data-tab="shots" aria-selected="false" aria-controls="panel-shots" tabindex="-1">Screenshots</button>
        </div>
        <div id="panel-activity" class="tab-panel" role="tabpanel" aria-labelledby="tab-activity">
          ${activityFilterForm()}
          <div id="activity-slot">${activity}</div>
        </div>
        <div id="panel-shots" class="tab-panel" role="tabpanel" aria-labelledby="tab-shots" hidden>
          <div id="shot-slot">${shotGrid(shots)}</div>
        </div>
      </aside>
    </div>
    ${workspaceTabs()}`,
    {
      galleries: { view: shots },
      streamDevice: device?.deviceId || '',
      personKey: device?.deviceId ? '' : (options.personKey || ''),
      board: true,
      alerts,
      alertIds: alerts.map((alert) => alert.id),
      workspace: true,
      subtitle: options.heading
    }
  );
}

function devicePage(device, reports, entries, notice) {
  const signedIn = device?.loggedIn === true && Boolean(emailKey(device?.email));
  const heading = signedIn ? device.email : 'Not signed in';
  const sub = [device?.hostname || 'This computer', !signedIn && device?.email ? `Last email ${device.email}` : '']
    .filter(Boolean)
    .join(' · ');
  return workspacePage({
    title: heading,
    heading,
    sub,
    device,
    reports,
    entries,
    notice,
    email: device?.email || '',
    tools: deviceTools(device)
  });
}

function userPage(label, key, reports, entries, notice) {
  return workspacePage({
    title: label,
    heading: label,
    sub: 'No app open',
    device: null,
    reports,
    entries,
    notice,
    email: key ? label : '',
    personKey: key || '__none__',
    tools: '<p class="meta">This Dat Desk is not open right now.</p>'
  });
}

function displayEmail(key, reports, entries, presence) {
  if (!key) return 'No email';
  for (const device of Object.values(presence || {})) {
    if (emailKey(device?.email) === key && device.email) return device.email;
  }
  for (const entry of entries || []) {
    if (emailKey(entry.email) === key && entry.email) return entry.email;
  }
  for (const report of reports || []) {
    if (emailKey(report.email) === key && report.email) return report.email;
  }
  return key;
}

function shotGrid(shots) {
  if (!shots.length) return '<p class="empty">No screenshots for this email yet.</p>';
  return `<div class="shots">${shots
    .map(
      (shot, index) => `<button type="button" class="thumb" data-gallery="view" data-index="${index}" aria-label="Open screenshot, ${escapeHtml(shot.caption)}">
        <img src="${escapeHtml(shot.src)}" alt="" />
        <span class="thumb-cap">${escapeHtml(shot.caption)}</span>
      </button>`
    )
    .join('')}</div>`;
}

function deviceTools(device) {
  if (!device || !isOnline(device)) {
    return '<p class="meta">This Dat Desk is not open right now.</p>';
  }
  const signedIn = device.loggedIn === true && Boolean(emailKey(device.email));
  const pills = [
    '<span class="pill live">Live</span>',
    signedIn ? '<span class="pill">Signed in</span>' : '<span class="pill">Sign-in screen</span>',
    device.allowRemote === true ? '<span class="pill ok">Capture on</span>' : '<span class="pill warn">Capture off</span>',
    device.allowLive === true ? '<span class="pill stream">Live view on</span>' : '<span class="pill warn">Live view off</span>'
  ].join('');
  return `<div class="pills">${pills}</div>${captureForm(device, 'device')}${remoteActionForm(device)}`;
}

function remoteActionForm(device) {
  const waiting = freshCommand(device);
  const result = waiting ? null : freshCommandResult(device);
  const disabled = waiting ? ' disabled' : '';
  const buttons = REMOTE_ACTIONS.filter((action) => !action.form).map((action) => {
    const confirm = action.confirm ? ` onclick="return confirm('${action.confirm.replace(/'/g, '')}')"` : '';
    const danger = action.danger ? ' danger' : '';
    return `<button type="submit" name="type" value="${action.type}" class="${danger.trim()}"${disabled}${confirm}>${escapeHtml(action.label)}</button>`;
  }).join('');
  let status = '<p class="meta remote-note">Control this Dat Desk without opening the computer.</p>';
  if (waiting) {
    status = `<p class="meta remote-note">Waiting for this Dat Desk to ${escapeHtml(remoteVerb(waiting.type))}.</p>`;
  } else if (result) {
    const label = REMOTE_ACTIONS.find((action) => action.type === result.type)?.label || 'That action';
    status = result.status === 'error'
      ? `<p class="meta warn remote-note">${escapeHtml(label)} failed. ${escapeHtml(result.error || '')}</p>`
      : `<p class="meta ok remote-note">${escapeHtml(label)} is done.</p>`;
  }
  return `${signInForm(device, waiting)}<form method="post" action="/remote-commands" class="remote-actions">${buttons}
    <input type="hidden" name="deviceId" value="${escapeHtml(device.deviceId)}" />
    <input type="hidden" name="returnTo" value="device" />
  </form>${status}`;
}

/** Shown while the app sits on its sign-in screen: support signs the person in for them. */
function signInForm(device, waiting) {
  if (device.loggedIn === true) return '';
  const id = escapeHtml(device.deviceId);
  const disabled = waiting ? ' disabled' : '';
  return `<form method="post" action="/remote-commands" class="signin-form" autocomplete="off">
    <h2>Sign in this Dat Desk</h2>
    <p class="meta">The app is on its sign-in screen. Enter the person's Dat Desk login and it signs in on that computer.</p>
    <div class="signin-fields">
      <label>Email
        <input type="email" name="email" value="${escapeHtml(device.email || '')}" required autocomplete="off" spellcheck="false" />
      </label>
      <label>Password
        <input type="password" name="password" required autocomplete="new-password" />
      </label>
      <button type="submit"${disabled}>Sign in</button>
    </div>
    <input type="hidden" name="type" value="sign-in" />
    <input type="hidden" name="deviceId" value="${id}" />
    <input type="hidden" name="returnTo" value="device" />
  </form>`;
}

function saveReport(body) {
  const source = body?.source === 'admin' ? 'admin' : body?.source === 'alert' ? 'alert' : 'user';
  let message = String(body?.message || '').trim();
  if (!message && source === 'admin') message = 'Screenshot requested by support.';
  if (!message) {
    const error = new Error('Add a short message about the issue.');
    error.status = 400;
    throw error;
  }
  if (message.length > MAX_MESSAGE) {
    const error = new Error('That message is too long.');
    error.status = 400;
    throw error;
  }
  const shots = Array.isArray(body?.screenshots) ? body.screenshots.slice(0, MAX_SHOTS) : [];
  if (!shots.length) {
    const error = new Error('A screenshot is required.');
    error.status = 400;
    throw error;
  }

  const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(DATA_DIR, id);
  fs.mkdirSync(dir, { recursive: true });
  const files = [];
  shots.forEach((shot, index) => {
    const buf = Buffer.from(String(shot?.data || ''), 'base64');
    if (buf.length < 4 || buf.length > MAX_SHOT_BYTES || buf[0] !== 0xff || buf[1] !== 0xd8) {
      const error = new Error('The screenshot was not a valid image.');
      error.status = 400;
      throw error;
    }
    const name = `screen-${index + 1}.jpg`;
    fs.writeFileSync(path.join(dir, name), buf);
    files.push(name);
  });

  const report = {
    id,
    message,
    email: String(body.email || '').slice(0, 200),
    userId: String(body.userId || '').slice(0, 80),
    appVersion: String(body.appVersion || '').slice(0, 40),
    platform: String(body.platform || '').slice(0, 40),
    hostname: String(body.hostname || '').slice(0, 120),
    deviceId: deviceKey(body.deviceId),
    source,
    requestId: String(body.requestId || '').slice(0, 80),
    createdAt: new Date().toISOString(),
    files
  };
  fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report, null, 2));
  rememberAlert(report, body);

  if (report.requestId) {
    const presence = loadPresence();
    let changed = false;
    for (const device of Object.values(presence)) {
      if (device?.pending?.id === report.requestId) {
        device.pending = null;
        changed = true;
      }
    }
    if (changed) savePresence(presence);
  }
  return report;
}

function upsertPresence(body) {
  const deviceId = deviceKey(body?.deviceId);
  if (!deviceId) {
    const error = new Error('This Dat Desk needs a restart before it can show up as live.');
    error.status = 400;
    throw error;
  }
  const email = String(body?.email || '').trim().slice(0, 200);
  const loggedIn = body?.loggedIn === true && Boolean(emailKey(email));
  const presence = loadPresence();
  const previous = presence[deviceId] || {};
  let pending = freshPending(previous);
  const command = freshCommand(previous);
  if (command && !command.deliveredAt) command.deliveredAt = new Date().toISOString();
  const commandResult = freshCommandResult(previous);
  const allowRemote = body?.allowRemote === true;
  const allowLive = body?.allowLive === true;
  if (!allowRemote) pending = null;
  if (!allowLive) liveFrames.delete(deviceId);
  presence[deviceId] = {
    deviceId,
    email,
    loggedIn,
    userId: loggedIn ? String(body?.userId || '').slice(0, 80) : '',
    allowRemote,
    allowLive,
    hostname: String(body?.hostname || '').slice(0, 120),
    appVersion: String(body?.appVersion || '').slice(0, 40),
    platform: String(body?.platform || '').slice(0, 40),
    lastSeen: new Date().toISOString(),
    pending,
    command,
    commandResult,
    lastCommand: previous.lastCommand || null
  };
  savePresence(presence);
  return {
    request: allowRemote && pending ? { id: pending.id, deviceId, email } : null,
    watch: allowLive && isWatched(deviceId),
    liveGeneration: liveSessions.get(deviceId)?.generation || 0,
    command: command ? commandForDevice(command, deviceId) : null
  };
}

function commandForDevice(command, deviceId) {
  const out = { id: command.id, type: command.type, deviceId };
  if (command.type === 'sign-in') {
    const secret = commandSecrets.get(command.id);
    if (!secret || secret.deviceId !== deviceId) return null;
    out.email = secret.email;
    out.password = secret.password;
  }
  return out;
}

function sweepSecrets() {
  const now = Date.now();
  for (const [id, secret] of commandSecrets) {
    if (now > secret.expires) commandSecrets.delete(id);
  }
}
setInterval(sweepSecrets, 15000).unref();

function isWatched(deviceId) {
  return liveSessions.get(deviceId)?.wanted === true;
}

function liveSession(deviceId) {
  if (!liveSessions.has(deviceId)) {
    liveSessions.set(deviceId, {
      wanted: false,
      generation: 0,
      offer: '',
      answer: '',
      screens: [],
      screenIndex: 0
    });
  }
  return liveSessions.get(deviceId);
}

function cleanScreens(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 8).map((item, index) => ({
    index,
    name: String(item?.name || `Screen ${index + 1}`).replace(/\s+/g, ' ').trim().slice(0, 80) || `Screen ${index + 1}`
  }));
}

function decodeLiveJpeg(data) {
  const buf = Buffer.from(String(data || ''), 'base64');
  if (buf.length < 4 || buf.length > LIVE_MAX_BYTES || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  return buf;
}

function writeMjpeg(res, buffer) {
  res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${buffer.length}\r\n\r\n`);
  res.write(buffer);
  res.write('\r\n');
}

function publishLive(deviceId, screens) {
  liveFrames.set(deviceId, { at: Date.now(), screens });
  const set = liveWatchers.get(deviceId);
  if (!set) return;
  for (const watcher of set) {
    const buffer = screens[watcher.index];
    if (!buffer || watcher.res.writableEnded) {
      set.delete(watcher);
      continue;
    }
    try {
      writeMjpeg(watcher.res, buffer);
    } catch {
      set.delete(watcher);
    }
  }
  if (!set.size) liveWatchers.delete(deviceId);
}

function reportsForEmail(reports, email) {
  const key = emailKey(email);
  return reports.filter((report) => emailKey(report.email) === key);
}

function queueCapture(deviceId) {
  const key = deviceKey(deviceId);
  const presence = loadPresence();
  const device = key ? presence[key] : null;
  const fail = (code) => {
    const error = new Error(code);
    error.code = code;
    error.device = device;
    throw error;
  };
  if (!device || !isOnline(device)) fail('offline');
  if (device.allowRemote !== true) fail('denied');
  if (freshPending(device)) fail('queued');
  device.pending = {
    id: `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`,
    createdAt: new Date().toISOString()
  };
  presence[key] = device;
  savePresence(presence);
  return device;
}

function queueRemote(deviceId, type, extra = {}) {
  const action = String(type || '');
  const key = deviceKey(deviceId);
  const presence = loadPresence();
  const device = key ? presence[key] : null;
  const fail = (code) => {
    const error = new Error(code);
    error.code = code;
    error.device = device;
    throw error;
  };
  if (!REMOTE_TYPES.has(action)) fail('bad');
  if (!device || !isOnline(device)) fail('offline');
  if (freshCommand(device)) fail('busy');
  const email = String(extra.email || '').trim().slice(0, 200);
  const password = String(extra.password || '');
  if (action === 'sign-in') {
    if (device.loggedIn === true) fail('signedin');
    if (!email || !password || password.length > 500) fail('missing');
  }
  device.command = {
    id: `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`,
    type: action,
    createdAt: new Date().toISOString()
  };
  if (action === 'sign-in') {
    device.command.email = email;
    commandSecrets.set(device.command.id, {
      deviceId: key,
      email,
      password,
      expires: Date.now() + REQUEST_MS
    });
  }
  device.lastCommand = { id: device.command.id, type: action };
  device.commandResult = null;
  presence[key] = device;
  savePresence(presence);
  return device;
}

const ACTIVITY_EVENTS = new Set([
  'login',
  'logout',
  'open_dat',
  'dat_opened',
  'dat_closed',
  'dat_shown',
  'dat_hidden',
  'signed_out',
  'screenshot',
  'settings',
  'alert',
  'remote'
]);
const ACTIVITY_KEEP = 4000;
let activityWrite = Promise.resolve();

function loadActivity() {
  try {
    const raw = JSON.parse(fs.readFileSync(ACTIVITY_PATH, 'utf8'));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

function saveActivity(list) {
  fs.mkdirSync(path.dirname(ACTIVITY_PATH), { recursive: true });
  fs.writeFileSync(ACTIVITY_PATH, JSON.stringify(list));
}

function cleanActivityDetail(event, raw) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const detail = {};
  if (event === 'open_dat') {
    detail.source = 'button';
    const result = String(source.result || '');
    if (['already_open', 'cancelled', 'timezone', 'failed'].includes(result)) detail.result = result;
  }
  if (event === 'dat_opened' || event === 'dat_closed') {
    const opened = Date.parse(source.openedAt || '');
    if (Number.isFinite(opened)) detail.openedAt = new Date(opened).toISOString();
  }
  if (event === 'dat_closed') {
    const ms = Number(source.durationMs);
    if (Number.isFinite(ms) && ms >= 0 && ms < 14 * 24 * 60 * 60 * 1000) detail.durationMs = Math.round(ms);
    const reason = String(source.reason || '');
    detail.reason = ['quit', 'logout', 'banned', 'closed'].includes(reason) ? reason : 'closed';
  }
  if (event === 'signed_out') {
    detail.reason = source.reason === 'banned' ? 'banned' : 'other_device';
  }
  if (event === 'screenshot') {
    detail.source = source.source === 'admin' ? 'admin' : 'user';
  }
  if (event === 'settings') {
    if (typeof source.allowRemote === 'boolean') detail.allowRemote = source.allowRemote;
    if (typeof source.allowLive === 'boolean') detail.allowLive = source.allowLive;
  }
  if (event === 'alert') {
    detail.app = String(source.app || '').replace(/\s+/g, ' ').trim().slice(0, 80);
    detail.title = String(source.title || '').replace(/\s+/g, ' ').trim().slice(0, 180);
  }
  if (event === 'remote') {
    const action = String(source.action || '');
    if (REMOTE_TYPES.has(action)) detail.action = action;
    if (source.ok === false) detail.ok = false;
    const error = String(source.error || '').replace(/\s+/g, ' ').trim().slice(0, 180);
    if (error) detail.error = error;
  }
  return detail;
}

function recordActivity(body) {
  const event = String(body?.event || '');
  const email = String(body?.email || '').trim().slice(0, 200);
  const deviceId = deviceKey(body?.deviceId);
  if (!ACTIVITY_EVENTS.has(event) || (!email && !deviceId)) return null;
  const at = new Date(body?.at || Date.now());
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    at: Number.isNaN(at.getTime()) ? new Date().toISOString() : at.toISOString(),
    event,
    email,
    userId: String(body?.userId || '').trim().slice(0, 80),
    deviceId,
    hostname: String(body?.hostname || '').trim().slice(0, 120),
    platform: String(body?.platform || '').trim().slice(0, 80),
    appVersion: String(body?.appVersion || '').trim().slice(0, 40),
    detail: cleanActivityDetail(event, body?.detail)
  };
  activityWrite = activityWrite
    .then(() => {
      const list = loadActivity();
      list.unshift(entry);
      saveActivity(list.slice(0, ACTIVITY_KEEP));
    })
    .catch((err) => {
      console.warn('[TRACKINGEYE] Activity save failed:', err.message);
    });
  return entry;
}

function formatDuration(ms) {
  const total = Math.max(0, Math.round(Number(ms) / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function activityText(entry) {
  const detail = entry?.detail || {};
  if (entry.event === 'login') return 'Signed in';
  if (entry.event === 'logout') return 'Signed out';
  if (entry.event === 'open_dat') {
    if (detail.result === 'already_open') return 'Pressed Open DAT. DAT was already open.';
    if (detail.result === 'cancelled') return 'Pressed Open DAT. The window was closed while it was starting.';
    if (detail.result === 'timezone') return 'Pressed Open DAT. The PC time zone blocked it.';
    if (detail.result === 'failed') return 'Pressed Open DAT. DAT did not open.';
    return 'Pressed Open DAT';
  }
  if (entry.event === 'dat_opened') return 'DAT opened';
  if (entry.event === 'dat_closed') {
    const stay = Number.isFinite(detail.durationMs) ? formatDuration(detail.durationMs) : '';
    return stay ? `Left DAT after ${stay}` : 'Left DAT';
  }
  if (entry.event === 'dat_hidden') return 'Sent the DAT window to the tray';
  if (entry.event === 'dat_shown') return 'Brought the DAT window back';
  if (entry.event === 'signed_out') {
    return detail.reason === 'banned' ? 'Signed out because the account was banned' : 'Signed out because this account signed in on another device';
  }
  if (entry.event === 'screenshot') {
    return detail.source === 'admin' ? 'Screenshot taken by support' : 'Screenshot sent';
  }
  if (entry.event === 'alert') {
    return detail.app ? `Alert: ${detail.app}` : 'Alert';
  }
  if (entry.event === 'remote') {
    const verb = remoteVerb(detail.action);
    if (detail.ok === false) {
      return detail.error ? `Could not ${verb}. ${detail.error}` : `Could not ${verb}.`;
    }
    return `Support asked this Dat Desk to ${verb}`;
  }
  if (entry.event === 'settings') {
    const capture = detail.allowRemote === true ? 'Capture on' : detail.allowRemote === false ? 'Capture off' : '';
    const live = detail.allowLive === true ? 'Live on' : detail.allowLive === false ? 'Live off' : '';
    return ['Changed permissions', capture, live].filter(Boolean).join(' · ');
  }
  return entry.event;
}

function activityDetail(entry) {
  const detail = entry?.detail || {};
  const where = [
    entry.hostname || '',
    entry.platform || '',
    entry.appVersion ? `Dat Desk ${entry.appVersion}` : ''
  ].filter(Boolean);
  const bits = [];
  if (entry.event === 'dat_closed') {
    if (detail.openedAt) bits.push(`Opened ${formatWhen(detail.openedAt)}`);
    bits.push(
      detail.reason === 'logout'
        ? 'Ended when they signed out'
        : detail.reason === 'quit'
          ? 'Ended when the app quit'
          : detail.reason === 'banned'
            ? 'Ended because the account was banned'
            : 'Ended when DAT was closed'
    );
  }
  if (entry.event === 'dat_hidden') bits.push('DAT stayed open in the tray.');
  if (entry.event === 'dat_shown') bits.push('The visit kept running.');
  if (where.length) bits.push(where.join(' · '));
  return bits.join(' · ');
}

function activityKind(event) {
  if (['login', 'logout', 'signed_out'].includes(event)) return 'signin';
  if (event === 'open_dat') return 'open';
  if (['dat_opened', 'dat_closed', 'dat_shown', 'dat_hidden'].includes(event)) return 'visit';
  if (event === 'screenshot' || event === 'alert') return 'screen';
  if (event === 'settings') return 'settings';
  return '';
}

function activityFilters(query) {
  const kind = String(query?.kind || '');
  const range = String(query?.range || '');
  return {
    q: String(query?.q || '').trim().toLowerCase().slice(0, 120),
    email: String(query?.email || '').trim().toLowerCase().slice(0, 200),
    kind: ['signin', 'open', 'visit', 'screen', 'settings'].includes(kind) ? kind : '',
    range: ['today', '7', '30'].includes(range) ? range : '',
    computer: String(query?.computer || '').trim().toLowerCase().slice(0, 80)
  };
}

function activityInRange(entry, range) {
  const at = Date.parse(entry.at || '');
  if (!Number.isFinite(at)) return false;
  if (!range) return true;
  if (range === 'today') {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    return at >= start.getTime();
  }
  const days = range === '7' ? 7 : 30;
  return Date.now() - at <= days * 24 * 60 * 60 * 1000;
}

function activityPeople(entries) {
  const people = new Map();
  for (const entry of entries) {
    const key = emailKey(entry.email) || '__none__';
    if (!people.has(key)) {
      people.set(key, {
        key,
        email: entry.email || 'No email',
        lastAt: entry.at,
        signins: 0,
        presses: 0,
        visits: 0,
        shots: 0,
        totalMs: 0
      });
    }
    const person = people.get(key);
    if (entry.email) person.email = entry.email;
    if (entry.event === 'login') person.signins += 1;
    if (entry.event === 'open_dat' && !entry.detail?.result) person.presses += 1;
    if (entry.event === 'dat_opened') person.visits += 1;
    if (entry.event === 'screenshot') person.shots += 1;
    if (entry.event === 'dat_closed') person.totalMs += Number(entry.detail?.durationMs) || 0;
  }
  return [...people.values()];
}

function activityTimeline(entries) {
  if (!entries.length) return '<p class="empty">Nothing matches these filters.</p>';
  let day = '';
  const parts = ['<div class="timeline">'];
  for (const entry of entries.slice(0, 400)) {
    const when = new Date(entry.at || '');
    const label = Number.isNaN(when.getTime())
      ? ''
      : when.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric', year: 'numeric' });
    if (label && label !== day) {
      day = label;
      parts.push(`<h3 class="day-label">${escapeHtml(label)}</h3>`);
    }
    const extra = activityDetail(entry);
    parts.push(`<article class="event">
      <p class="meta">${escapeHtml(formatWhen(entry.at))}</p>
      <strong>${escapeHtml(activityText(entry))}</strong>
      ${extra ? `<p class="meta">${escapeHtml(extra)}</p>` : ''}
    </article>`);
  }
  parts.push('</div>');
  return parts.join('');
}

function activityPanel(entries, query) {
  const filters = activityFilters(query || {});
  const email = emailKey(query?.email);
  const deviceId = deviceKey(query?.deviceId);
  const mine = (entries || []).filter((entry) => {
    if (!activityInRange(entry, filters.range)) return false;
    if (email && emailKey(entry.email) === email) return true;
    if (deviceId && entry.deviceId === deviceId && (!email || !emailKey(entry.email))) return true;
    return false;
  });
  const shown = filters.kind ? mine.filter((entry) => activityKind(entry.event) === filters.kind) : mine;
  const statsPerson = activityPeople(mine)[0];
  const latest = mine[0];
  const last = latest
    ? `<p class="last-recorded"><span>Last recorded</span><strong>${escapeHtml(activityText(latest))}</strong><span>${escapeHtml(formatWhen(latest.at))}</span></p>`
    : '';
  const stats = statsPerson
    ? `<div class="stat-row">
        <p><strong>${statsPerson.signins}</strong> sign-in${statsPerson.signins === 1 ? '' : 's'}</p>
        <p><strong>${statsPerson.presses}</strong> Open DAT</p>
        <p><strong>${statsPerson.visits}</strong> visit${statsPerson.visits === 1 ? '' : 's'}</p>
        <p><strong>${escapeHtml(formatDuration(statsPerson.totalMs))}</strong> in DAT</p>
        <p><strong>${statsPerson.shots}</strong> screenshot${statsPerson.shots === 1 ? '' : 's'}</p>
      </div>`
    : '';
  const capped = shown.slice(0, 200);
  const more = shown.length > 200 ? '<p class="meta">Showing the latest 200 events.</p>' : '';
  return `${last}${stats}${activityTimeline(capped)}${more}`;
}

function activityBody(entries, query) {
  const filters = activityFilters(query);
  const pool = entries.filter((entry) => {
    if (!activityInRange(entry, filters.range)) return false;
    if (filters.computer && !String(entry.hostname || '').toLowerCase().includes(filters.computer)) return false;
    return true;
  });
  const people = activityPeople(pool).filter((person) => !filters.q || person.email.toLowerCase().includes(filters.q) || person.key.includes(filters.q));
  const selected = people.find((person) => person.key === filters.email) || people[0] || null;
  const list = people.length
    ? `<div class="person-list" role="list">${people
        .map((person) => `<button type="button" class="person" data-email="${escapeHtml(person.key)}" aria-pressed="${selected && person.key === selected.key ? 'true' : 'false'}">
          <strong>${escapeHtml(person.email)}</strong>
          <span>${person.visits} visit${person.visits === 1 ? '' : 's'} · ${escapeHtml(formatDuration(person.totalMs))}</span>
        </button>`)
        .join('')}</div>`
    : '<p class="empty">No emails match these filters.</p>';
  const mine = selected
    ? pool.filter((entry) => (emailKey(entry.email) || '__none__') === selected.key)
    : [];
  const shown = filters.kind ? mine.filter((entry) => activityKind(entry.event) === filters.kind) : mine;
  const stats = selected
    ? `<div class="stat-row">
        <p><strong>${selected.signins}</strong> sign-in${selected.signins === 1 ? '' : 's'}</p>
        <p><strong>${selected.presses}</strong> Open DAT</p>
        <p><strong>${selected.visits}</strong> visit${selected.visits === 1 ? '' : 's'}</p>
        <p><strong>${escapeHtml(formatDuration(selected.totalMs))}</strong> in DAT</p>
        <p><strong>${selected.shots}</strong> screenshot${selected.shots === 1 ? '' : 's'}</p>
      </div>`
    : '';
  const heading = selected ? escapeHtml(selected.email) : 'Activity';
  return `<div class="activity-layout">
    ${list}
    <section>
      <div class="section-head"><h2>${heading}</h2><p>${shown.length} event${shown.length === 1 ? '' : 's'}</p></div>
      ${stats}
      ${activityTimeline(shown)}
    </section>
  </div>`;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: false }));

app.post('/api/activity', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false });
    return;
  }
  const entry = recordActivity(req.body || {});
  if (!entry) {
    res.status(400).json({ ok: false });
    return;
  }
  res.json({ ok: true });
});

app.get('/', (req, res) => {
  if (!isAdmin(req)) {
    res.type('html').send(loginPage(''));
    return;
  }
  const reports = listReports();
  const presence = loadPresence();
  const notice = inboxNotice(req.query.notice);
  const view = String(req.query.view || '');
  if (view) {
    const key = view === '__none__' ? '' : emailKey(view);
    const pick = bestDevice(
      Object.values(presence).filter((device) => emailKey(device.email) === key && device.deviceId)
    );
    if (pick) {
      res.redirect(`/device/${encodeURIComponent(pick.deviceId)}`);
      return;
    }
    res.redirect(`/user/${viewToken(key)}`);
    return;
  }
  res.type('html').send(inboxHome(reports, presence, loadActivity(), notice));
});

app.post('/login', (req, res) => {
  if (!safeEqual(req.body?.password || '', ADMIN_PASSWORD)) {
    res.status(401).type('html').send(loginPage('That password is not right.'));
    return;
  }
  res.setHeader(
    'Set-Cookie',
    `${COOKIE}=${adminCookie}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`
  );
  res.redirect('/');
});

app.post('/remote-commands', (req, res) => {
  if (!isAdmin(req)) {
    res.redirect('/');
    return;
  }
  const deviceId = deviceKey(req.body?.deviceId);
  try {
    const device = queueRemote(deviceId, req.body?.type, {
      email: req.body?.email,
      password: req.body?.password
    });
    res.redirect(`/device/${encodeURIComponent(device.deviceId)}?notice=sent`);
  } catch (err) {
    const notice = ['offline', 'busy', 'bad', 'signedin', 'missing'].includes(err.code) ? err.code : 'offline';
    if (deviceId) {
      res.redirect(`/device/${encodeURIComponent(deviceId)}?notice=${notice}`);
      return;
    }
    res.redirect(`/?notice=${notice}`);
  }
});

app.post('/api/command-result', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false });
    return;
  }
  const deviceId = deviceKey(req.body?.deviceId);
  const id = String(req.body?.id || '').slice(0, 80);
  if (!deviceId || !id) {
    res.status(400).json({ ok: false });
    return;
  }
  const presence = loadPresence();
  const device = presence[deviceId];
  // Accept late answers too: the command may have timed out while the app was still working.
  const known = device?.command?.id === id ? device.command : device?.lastCommand?.id === id ? device.lastCommand : null;
  if (!device || !known || !REMOTE_TYPES.has(known.type)) {
    res.json({ ok: true });
    return;
  }
  commandSecrets.delete(id);
  device.commandResult = {
    id,
    type: known.type,
    status: req.body?.status === 'error' ? 'error' : 'done',
    error: String(req.body?.error || '').replace(/\s+/g, ' ').trim().slice(0, 300),
    at: new Date().toISOString()
  };
  if (device.command?.id === id) device.command = null;
  presence[deviceId] = device;
  savePresence(presence);
  res.json({ ok: true });
});

app.post('/capture-requests', (req, res) => {
  if (!isAdmin(req)) {
    res.redirect('/');
    return;
  }
  try {
    const device = queueCapture(req.body?.deviceId);
    const notice = 'waiting';
    if (req.body?.returnTo === 'device') {
      res.redirect(`/device/${encodeURIComponent(device.deviceId)}?notice=${notice}`);
      return;
    }
    const view = viewToken(emailKey(device.email));
    res.redirect(`/?view=${view}&notice=${notice}`);
  } catch (err) {
    const notice = ['offline', 'denied', 'queued'].includes(err.code) ? err.code : 'offline';
    if (req.body?.returnTo === 'device' && err.device?.deviceId) {
      res.redirect(`/device/${encodeURIComponent(err.device.deviceId)}?notice=${notice}`);
      return;
    }
    const email = err.device?.email || '';
    const target = err.device ? `/?view=${viewToken(emailKey(email))}&notice=${notice}` : `/?notice=${notice}`;
    res.redirect(target);
  }
});

app.post('/api/presence', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false, message: 'TrackingEye rejected this report.' });
    return;
  }
  try {
    const result = upsertPresence(req.body || {});
    res.json({
      ok: true,
      request: result.request,
      watch: result.watch === true,
      liveGeneration: result.liveGeneration || 0,
      command: result.command || null
    });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message || 'Could not update presence.' });
  }
});

app.post('/api/reports', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false, message: 'TrackingEye rejected this report.' });
    return;
  }
  try {
    const report = saveReport(req.body || {});
    console.log('[TRACKINGEYE] Report', report.id, report.email || 'no-email', report.source);
    res.json({ ok: true, id: report.id });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message || 'Could not save the report.' });
  }
});

app.get('/reports/:id/files/:name', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).send('Sign in first.');
    return;
  }
  const id = String(req.params.id || '');
  const name = String(req.params.name || '');
  if (!/^[a-z0-9-]+$/i.test(id) || !/^screen-\d+\.jpg$/.test(name)) {
    res.status(404).end();
    return;
  }
  const root = path.resolve(DATA_DIR);
  const file = path.resolve(root, id, name);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {
    res.status(404).end();
    return;
  }
  res.setHeader('Content-Type', 'image/jpeg');
  res.setHeader('Cache-Control', 'private, no-store');
  fs.createReadStream(file).pipe(res);
});

app.post('/alerts/:id/dismiss', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  dismissAlerts(String(req.params.id || '').split(','), false);
  res.json({ ok: true });
});

app.post('/alerts/dismiss', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.slice(0, 500) : [];
  dismissAlerts(ids, req.body?.all === true);
  res.json({ ok: true, ...alertPayload() });
});

app.get('/fragment/board', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).end();
    return;
  }
  const reports = listReports();
  const presence = loadPresence();
  const entries = loadActivity();
  const devices = liveDevices(presence);
  const alerts = openAlerts();
  const alertIds = alerts.map((alert) => alert.deviceId).filter(Boolean);
  const signature = [
    reports.map((report) => report.id).join(','),
    devices
      .map((device) =>
        [device.deviceId, device.allowLive === true, device.allowRemote === true, device.loggedIn === true, device.email].join(':')
      )
      .join(','),
    alerts.map((alert) => alert.id).join(','),
    entries[0]?.id || ''
  ].join('|');
  res.json({
    live: deviceCards(devices, new Set(alertIds)),
    liveCount: devices.length,
    alerts: alertMarkup(alerts),
    alertIds: alerts.map((alert) => alert.id),
    alertCount: alerts.length,
    people: emailDirectory(reports, presence, entries, alerts),
    peopleSignature: signature
  });
});

app.get('/fragment/device/:deviceId', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).end();
    return;
  }
  const id = deviceKey(req.params.deviceId);
  const device = id ? loadPresence()[id] : null;
  const reports = reportsForEmail(listReports(), device?.email || '');
  const shots = flattenShots(reports);
  res.json({
    tools: deviceTools(device),
    shots: shotGrid(shots),
    galleries: { view: shots },
    activity: activityPanel(loadActivity(), {
      email: device?.email || '',
      deviceId: id,
      kind: req.query.kind,
      range: req.query.range
    }),
    allowLive: device?.allowLive === true && isOnline(device),
    online: Boolean(device && isOnline(device))
  });
});

app.get('/activity', (req, res) => {
  res.redirect('/');
});

app.get('/user/:key', (req, res) => {
  if (!isAdmin(req)) {
    res.redirect('/');
    return;
  }
  const raw = String(req.params.key || '');
  const key = raw === '__none__' ? '' : emailKey(raw);
  const reports = listReports();
  const presence = loadPresence();
  const entries = loadActivity();
  const pick = bestDevice(
    Object.values(presence).filter((device) => emailKey(device.email) === key && device.deviceId)
  );
  if (pick) {
    res.redirect(`/device/${encodeURIComponent(pick.deviceId)}`);
    return;
  }
  const notice = inboxNotice(req.query.notice);
  res.type('html').send(userPage(
    displayEmail(key, reports, entries, presence),
    key,
    reportsForEmail(reports, key),
    entries,
    notice
  ));
});

app.get('/fragment/user/:key', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).end();
    return;
  }
  const raw = String(req.params.key || '');
  const key = raw === '__none__' ? '' : emailKey(raw);
  const reports = listReports();
  const entries = loadActivity();
  const label = displayEmail(key, reports, entries, loadPresence());
  const shots = flattenShots(reportsForEmail(reports, key ? label : ''));
  res.json({
    shots: shotGrid(shots),
    galleries: { view: shots },
    activity: activityPanel(entries, {
      email: key ? label : '',
      kind: req.query.kind,
      range: req.query.range
    })
  });
});

app.get('/fragment/activity', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).end();
    return;
  }
  res.json({ html: activityBody(loadActivity(), req.query) });
});

app.get('/device/:deviceId', (req, res) => {
  if (!isAdmin(req)) {
    res.redirect('/');
    return;
  }
  const id = deviceKey(req.params.deviceId);
  if (!id) {
    res.redirect('/');
    return;
  }
  const device = loadPresence()[id] || {
    deviceId: id,
    email: '',
    loggedIn: false,
    allowRemote: false,
    allowLive: false
  };
  const notice = inboxNotice(req.query.notice);
  res.type('html').send(devicePage(device, reportsForEmail(listReports(), device.email), loadActivity(), notice));
});

app.post('/watch', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const id = deviceKey(req.body?.deviceId);
  const device = id ? loadPresence()[id] : null;
  if (!device || !isOnline(device)) {
    res.json({ ok: false, reason: 'offline' });
    return;
  }
  if (device.allowLive !== true) {
    res.json({ ok: false, reason: 'denied' });
    return;
  }
  const session = liveSession(id);
  session.wanted = true;
  session.generation += 1;
  session.offer = '';
  session.answer = '';
  session.screens = [];
  session.screenIndex = 0;
  res.json({ ok: true, generation: session.generation });
});

app.post('/watch/stop', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const id = deviceKey(req.body?.deviceId);
  const session = id ? liveSessions.get(id) : null;
  if (session) {
    session.wanted = false;
    session.offer = '';
    session.answer = '';
  }
  res.json({ ok: true });
});

app.get('/api/live-signal', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false });
    return;
  }
  const id = deviceKey(req.query.deviceId);
  const generation = Number(req.query.generation);
  const session = id ? liveSessions.get(id) : null;
  if (!session || !session.wanted || session.generation !== generation) {
    res.json({ wanted: false, generation: session?.generation || 0, answer: '' });
    return;
  }
  res.json({
    wanted: true,
    generation,
    answer: session.answer || '',
    screenIndex: Number(session.screenIndex) || 0
  });
});

app.post('/api/live-signal', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false });
    return;
  }
  const id = deviceKey(req.body?.deviceId);
  const generation = Number(req.body?.generation);
  const session = id ? liveSessions.get(id) : null;
  if (!session || !session.wanted || session.generation !== generation) {
    res.json({ ok: false, wanted: false });
    return;
  }
  const offer = String(req.body?.offer || '');
  if (offer.length > 0 && offer.length < 200000) session.offer = offer;
  if (Array.isArray(req.body?.screens)) {
    session.screens = cleanScreens(req.body.screens);
    if (session.screenIndex >= session.screens.length) session.screenIndex = 0;
  }
  res.json({ ok: true, wanted: true });
});

app.get('/api/webrtc/:deviceId', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const session = liveSessions.get(deviceKey(req.params.deviceId));
  res.json({
    wanted: session?.wanted === true,
    generation: session?.generation || 0,
    offer: session?.offer || '',
    screens: session?.screens || [],
    screenIndex: Number(session?.screenIndex) || 0
  });
});

app.post('/api/webrtc/:deviceId', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const session = liveSessions.get(deviceKey(req.params.deviceId));
  const generation = Number(req.body?.generation);
  if (!session || !session.wanted || session.generation !== generation) {
    res.json({ ok: false });
    return;
  }
  const answer = String(req.body?.answer || '');
  if (answer.length > 0 && answer.length < 200000) session.answer = answer;
  res.json({ ok: true });
});

app.post('/api/webrtc/:deviceId/screen', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const session = liveSessions.get(deviceKey(req.params.deviceId));
  const index = Number(req.body?.index);
  const count = session?.screens?.length || 0;
  if (!session || !session.wanted || !Number.isInteger(index) || index < 0 || (count && index >= count)) {
    res.json({ ok: false });
    return;
  }
  session.screenIndex = index;
  res.json({ ok: true, screenIndex: index });
});

app.get('/api/live/:deviceId', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).json({ ok: false });
    return;
  }
  const id = deviceKey(req.params.deviceId);
  const device = id ? loadPresence()[id] : null;
  const frames = id ? liveFrames.get(id) : null;
  const fresh = Boolean(frames && Date.now() - frames.at < 5000);
  res.json({
    ok: true,
    allowLive: device?.allowLive === true && isOnline(device),
    online: Boolean(device && isOnline(device)),
    screens: fresh ? frames.screens.length : 0
  });
});

app.post('/api/live', (req, res) => {
  if (!safeEqual(req.get('x-ingest-key') || '', INGEST_KEY)) {
    res.status(401).json({ ok: false, message: 'TrackingEye rejected this report.' });
    return;
  }
  const id = deviceKey(req.body?.deviceId);
  const device = id ? loadPresence()[id] : null;
  if (!device || device.allowLive !== true || !isWatched(id)) {
    res.json({ ok: false, watch: false });
    return;
  }
  const incoming = Array.isArray(req.body?.screens) ? req.body.screens.slice(0, MAX_SHOTS) : [];
  const screens = [];
  for (const shot of incoming) {
    const buf = decodeLiveJpeg(shot?.data);
    if (!buf) {
      res.status(400).json({ ok: false, watch: true, message: 'The live frame was not a valid image.' });
      return;
    }
    screens.push(buf);
  }
  if (!screens.length) {
    res.status(400).json({ ok: false, watch: true, message: 'A live frame is required.' });
    return;
  }
  publishLive(id, screens);
  res.json({ ok: true, watch: isWatched(id) });
});

app.get('/live/:deviceId/:index', (req, res) => {
  if (!isAdmin(req)) {
    res.status(401).end();
    return;
  }
  const id = deviceKey(req.params.deviceId);
  const index = Number(req.params.index);
  const device = id ? loadPresence()[id] : null;
  if (!device || device.allowLive !== true || !Number.isInteger(index) || index < 0 || index >= MAX_SHOTS) {
    res.status(404).end();
    return;
  }
  res.writeHead(200, {
    'Content-Type': 'multipart/x-mixed-replace; boundary=frame',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    Connection: 'keep-alive',
    Pragma: 'no-cache'
  });
  const watcher = { res, index };
  const set = liveWatchers.get(id) || new Set();
  set.add(watcher);
  liveWatchers.set(id, set);
  const current = liveFrames.get(id);
  if (current?.screens[index]) writeMjpeg(res, current.screens[index]);
  const keep = setInterval(() => {
    const currentDevice = loadPresence()[id];
    if (!currentDevice || currentDevice.allowLive !== true || !isOnline(currentDevice) || !isWatched(id)) {
      res.end();
      return;
    }
  }, 3000);
  req.on('close', () => {
    clearInterval(keep);
    set.delete(watcher);
    if (!set.size) liveWatchers.delete(id);
  });
});

app.listen(PORT, HOST, () => {
  console.log(`[TRACKINGEYE] Inbox at http://${HOST}:${PORT}`);
});
