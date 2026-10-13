'use strict';

const fs = require('fs');
const path = require('path');

const SHOTS_PER_PAGE = 24;
const ROWS_PER_PAGE = 100;
const DAY_MS = 24 * 60 * 60 * 1000;
const TABS = [
  { key: 'shots', label: 'Screenshots' },
  { key: 'activity', label: 'Activity' },
  { key: 'alerts', label: 'Alerts' },
  { key: 'cleanup', label: 'Clean up' }
];
const RANGES = [
  ['', 'All time'],
  ['today', 'Today'],
  ['7', 'Last 7 days'],
  ['30', 'Last 30 days'],
  ['older7', 'Older than 7 days'],
  ['older30', 'Older than 30 days'],
  ['older90', 'Older than 90 days']
];
const SOURCES = [
  ['', 'All screenshots'],
  ['user', 'Sent from the app'],
  ['admin', 'Requested by support'],
  ['alert', 'Code editor alerts']
];
const KINDS = [
  ['', 'Everything'],
  ['signin', 'Sign in and out'],
  ['open', 'Open DAT'],
  ['visit', 'Time in DAT'],
  ['screen', 'Screenshots and alerts'],
  ['settings', 'Capture and live'],
  ['remote', 'Remote actions']
];
const STATUSES = [
  ['', 'Open and dismissed'],
  ['open', 'Open'],
  ['dismissed', 'Dismissed']
];
const CLEANUP_WHAT = [
  ['shots', 'Screenshots'],
  ['activity', 'Activity'],
  ['alerts', 'Alerts'],
  ['all', 'Everything']
];
const CLEANUP_AGE = [
  ['7', '7 days'],
  ['30', '30 days'],
  ['90', '90 days']
];
const FILTER_KEYS = ['tab', 'email', 'range', 'source', 'kind', 'status', 'page'];

/**
 * The /manage page: delete screenshots, activity and alerts, one at a time, by filter, by
 * email, or by age. `h` carries the helpers and storage functions that live in index.js.
 */
module.exports = function mountManage(app, h) {
  const { escapeHtml, emailKey, formatWhen } = h;

  function pick(value, list) {
    const text = String(value || '');
    return list.some(([key]) => key === text) ? text : '';
  }

  function readFilters(source) {
    const rawTab = String(source?.tab || '');
    const tab = TABS.some((item) => item.key === rawTab) ? rawTab : 'shots';
    const rawEmail = String(source?.email || '').trim();
    return {
      tab,
      email: rawEmail === '__none__' ? '__none__' : emailKey(rawEmail).slice(0, 200),
      range: pick(source?.range, RANGES),
      source: tab === 'shots' ? pick(source?.source, SOURCES) : '',
      kind: tab === 'activity' ? pick(source?.kind, KINDS) : '',
      status: tab === 'alerts' ? pick(source?.status, STATUSES) : '',
      page: Math.max(1, Math.floor(Number(source?.page)) || 1)
    };
  }

  function queryString(filters, extra = {}) {
    const params = new URLSearchParams();
    for (const key of FILTER_KEYS) {
      const value = key in extra ? extra[key] : filters[key];
      if (key === 'page' && Number(value) <= 1) continue;
      if (value) params.set(key, String(value));
    }
    for (const [key, value] of Object.entries(extra)) {
      if (!FILTER_KEYS.includes(key) && value !== undefined && value !== null) params.set(key, String(value));
    }
    const text = params.toString();
    return text ? `?${text}` : '';
  }

  function sameEmail(value, wanted) {
    if (!wanted) return true;
    return (emailKey(value) || '__none__') === wanted;
  }

  function inRange(iso, range) {
    if (!range) return true;
    const at = Date.parse(iso || '');
    if (!Number.isFinite(at)) return false;
    if (range === 'today') {
      const start = new Date();
      start.setHours(0, 0, 0, 0);
      return at >= start.getTime();
    }
    if (range.startsWith('older')) return Date.now() - at > Number(range.slice(5)) * DAY_MS;
    return Date.now() - at <= Number(range) * DAY_MS;
  }

  function kindOf(event) {
    return event === 'remote' ? 'remote' : h.activityKind(event);
  }

  function reportDir(id) {
    const text = String(id || '');
    if (!/^[a-z0-9-]+$/i.test(text)) return null;
    const root = path.resolve(h.DATA_DIR);
    const dir = path.resolve(root, text);
    return dir.startsWith(root + path.sep) ? dir : null;
  }

  function readReport(dir) {
    try {
      return JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  function removeDir(dir) {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }

  function matchReports(filters) {
    return h.listReports().filter((report) =>
      sameEmail(report.email, filters.email) &&
      inRange(report.createdAt, filters.range) &&
      (!filters.source || report.source === filters.source)
    );
  }

  function matchActivity(entries, filters) {
    return entries.filter((entry) =>
      sameEmail(entry.email, filters.email) &&
      inRange(entry.at, filters.range) &&
      (!filters.kind || kindOf(entry.event) === filters.kind)
    );
  }

  function matchAlerts(alerts, filters) {
    return alerts.filter((alert) =>
      sameEmail(alert.email, filters.email) &&
      inRange(alert.at, filters.range) &&
      (!filters.status || (filters.status === 'dismissed') === (alert.dismissed === true))
    );
  }

  /** Deletes whole report folders (the report and every screenshot in it). */
  function deleteReports(ids) {
    const counts = { r: 0, s: 0 };
    for (const id of new Set(ids)) {
      const dir = reportDir(id);
      if (!dir || !fs.existsSync(dir)) continue;
      const report = readReport(dir);
      removeDir(dir);
      counts.r += 1;
      counts.s += Array.isArray(report?.files) ? report.files.length : 0;
    }
    return counts;
  }

  /** Removes one screenshot; the report goes too once it has none left. */
  function removeShot(value) {
    const [id, file] = String(value || '').split('/');
    const dir = reportDir(id);
    const counts = { r: 0, s: 0 };
    if (!dir || !/^screen-\d+\.jpg$/.test(file || '')) return counts;
    const report = readReport(dir);
    if (!report || !Array.isArray(report.files) || !report.files.includes(file)) return counts;
    const left = report.files.filter((name) => name !== file);
    if (!left.length) {
      removeDir(dir);
      return { r: 1, s: 1 };
    }
    fs.rmSync(path.join(dir, file), { force: true, maxRetries: 5, retryDelay: 100 });
    report.files = left;
    fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report, null, 2));
    return { r: 0, s: 1 };
  }

  function deleteAlerts(test) {
    const list = h.loadAlerts();
    const keep = list.filter((alert) => !test(alert));
    if (keep.length !== list.length) h.saveAlerts(keep);
    return list.length - keep.length;
  }

  function deleteActivity(test) {
    return h.changeActivity((list) => list.filter((entry) => !test(entry)));
  }

  function idList(value) {
    return [].concat(value || []).map((id) => String(id)).filter(Boolean).slice(0, 5000);
  }

  function emailOptions(reports, entries, alerts) {
    const map = new Map();
    function add(email, field) {
      const key = emailKey(email) || '__none__';
      if (!map.has(key)) map.set(key, { key, label: key === '__none__' ? 'No email' : String(email).trim(), reports: 0, activity: 0, alerts: 0 });
      map.get(key)[field] += 1;
    }
    for (const report of reports) add(report.email, 'reports');
    for (const entry of entries) add(entry.email, 'activity');
    for (const alert of alerts) add(alert.email, 'alerts');
    return [...map.values()].sort((a, b) => {
      if (a.key === '__none__') return 1;
      if (b.key === '__none__') return -1;
      return a.label.localeCompare(b.label);
    });
  }

  function storageStats(reports) {
    let bytes = 0;
    let shots = 0;
    for (const report of reports) {
      const dir = reportDir(report.id);
      if (!dir) continue;
      for (const file of Array.isArray(report.files) ? report.files : []) {
        try {
          bytes += fs.statSync(path.join(dir, file)).size;
          shots += 1;
        } catch {
          // file already gone
        }
      }
    }
    return { bytes, shots };
  }

  function formatBytes(bytes) {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${bytes} B`;
  }

  function plural(count, word, many) {
    return `${count} ${count === 1 ? word : many || `${word}s`}`;
  }

  function sourceLabel(report) {
    if (report.source === 'alert') return 'Code editor alert';
    if (report.source === 'admin') return 'Requested by support';
    return report.appName ? `Sent from ${report.appName}` : 'Sent from the app';
  }

  function options(list, selected) {
    return list
      .map(([value, label]) => `<option value="${escapeHtml(value)}"${value === selected ? ' selected' : ''}>${escapeHtml(label)}</option>`)
      .join('');
  }

  function hiddenFilters(filters) {
    return FILTER_KEYS
      .filter((key) => filters[key] && !(key === 'page' && filters.page <= 1))
      .map((key) => `<input type="hidden" name="${key}" value="${escapeHtml(filters[key])}" />`)
      .join('');
  }

  function doneBanner(query) {
    if (query.err) return '<p class="banner warn-banner" role="alert">Could not finish deleting. Some records may be left. Try again.</p>';
    if (query.done !== '1') return '';
    const count = (key) => Math.max(0, Math.floor(Number(query[key])) || 0);
    const r = count('r');
    const s = count('s');
    const a = count('a');
    const l = count('l');
    const parts = [];
    if (s) parts.push(plural(s, 'screenshot') + (r ? ` (${plural(r, 'report')})` : ''));
    else if (r) parts.push(plural(r, 'report'));
    if (a) parts.push(plural(a, 'activity record'));
    if (l) parts.push(plural(l, 'alert'));
    if (!parts.length) return '<p class="banner" role="status">Nothing matched, so nothing was deleted.</p>';
    const text = parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : parts[0];
    return `<p class="banner ok-banner" role="status">Deleted ${escapeHtml(text)}.</p>`;
  }

  function pager(filters, page, pages) {
    if (pages <= 1) return '';
    const prev = page > 1
      ? `<a class="ghost small" href="/manage${queryString(filters, { page: page - 1 })}">Previous</a>`
      : '<span class="ghost small is-off" aria-disabled="true">Previous</span>';
    const next = page < pages
      ? `<a class="ghost small" href="/manage${queryString(filters, { page: page + 1 })}">Next</a>`
      : '<span class="ghost small is-off" aria-disabled="true">Next</span>';
    return `<nav class="pager" aria-label="Pages">${prev}<span class="meta">Page ${page} of ${pages}</span>${next}</nav>`;
  }

  function filterBar(filters, people) {
    const emailList = [['', 'All emails'], ...people.map((person) => [person.key, person.label])];
    if (filters.email && !people.some((person) => person.key === filters.email)) {
      emailList.push([filters.email, filters.email === '__none__' ? 'No email' : filters.email]);
    }
    const extra = filters.tab === 'shots'
      ? `<label>Source<select name="source">${options(SOURCES, filters.source)}</select></label>`
      : filters.tab === 'activity'
        ? `<label>Type<select name="kind">${options(KINDS, filters.kind)}</select></label>`
        : `<label>Status<select name="status">${options(STATUSES, filters.status)}</select></label>`;
    return `<form id="manage-filters" class="manage-filters" method="get" action="/manage">
      <input type="hidden" name="tab" value="${escapeHtml(filters.tab)}" />
      <label>Email<select name="email">${options(emailList, filters.email)}</select></label>
      <label>When<select name="range">${options(RANGES, filters.range)}</select></label>
      ${extra}
      <button type="submit" class="ghost">Apply</button>
      ${filters.email || filters.range || filters.source || filters.kind || filters.status
        ? `<a class="ghost reset" href="/manage?tab=${filters.tab}">Clear filters</a>`
        : ''}
    </form>`;
  }

  function bulkBar(total, noun, extra) {
    return `<div class="bulk-bar">
      <label class="check"><input type="checkbox" data-select-all /> Select all on this page</label>
      <span class="meta" data-selected-count>0 selected</span>
      <button type="submit" name="scope" value="selected" class="danger" data-needs-selection
        data-confirm="Delete the selected ${escapeHtml(noun)}? This cannot be undone." disabled>Delete selected</button>
      <button type="submit" name="scope" value="all" class="danger-outline"
        data-confirm="Delete all ${escapeHtml(plural(total, noun.replace(/s$/, ''), noun))} that match these filters${escapeHtml(extra || '')}? This cannot be undone.">Delete all ${total} matching</button>
    </div>`;
  }

  function shotsTab(filters) {
    const reports = matchReports(filters);
    const pages = Math.max(1, Math.ceil(reports.length / SHOTS_PER_PAGE));
    const page = Math.min(filters.page, pages);
    const slice = reports.slice((page - 1) * SHOTS_PER_PAGE, page * SHOTS_PER_PAGE);
    const shots = h.flattenShots(slice);
    const shotTotal = reports.reduce((sum, report) => sum + (Array.isArray(report.files) ? report.files.length : 0), 0);
    if (!reports.length) {
      return { html: '<p class="empty manage-empty">No screenshots match these filters.</p>', shots };
    }
    let index = 0;
    const cards = slice.map((report) => {
      const files = Array.isArray(report.files) ? report.files : [];
      const meta = [formatWhen(report.createdAt), sourceLabel(report), report.hostname, report.appVersion ? `v${report.appVersion}` : '']
        .filter(Boolean)
        .join(' · ');
      const thumbs = files.map((file, fileIndex) => {
        const shot = shots[index];
        const html = `<figure class="mshot">
          <button type="button" class="thumb" data-gallery="view" data-index="${index}" aria-label="Open screenshot, ${escapeHtml(shot?.caption || '')}">
            <img src="${escapeHtml(shot?.src || '')}" alt="" loading="lazy" />
          </button>
          <figcaption>
            <span>Screen ${fileIndex + 1}</span>
            <button type="submit" formaction="/manage/screenshots/remove" name="shot" value="${escapeHtml(`${report.id}/${file}`)}"
              class="link-danger" data-confirm="Remove this screenshot? This cannot be undone.">Remove</button>
          </figcaption>
        </figure>`;
        index += 1;
        return html;
      }).join('');
      return `<article class="report-card">
        <div class="report-head">
          <label class="check"><input type="checkbox" name="ids" value="${escapeHtml(report.id)}" data-row />
            <strong>${escapeHtml(report.email || 'No email')}</strong></label>
          <span class="meta">${escapeHtml(plural(files.length, 'screenshot'))}</span>
        </div>
        <p class="meta">${escapeHtml(meta)}</p>
        ${report.message ? `<p class="report-msg">${escapeHtml(report.message)}</p>` : ''}
        <div class="report-shots">${thumbs || '<p class="empty">No screenshot files left.</p>'}</div>
      </article>`;
    }).join('');
    const html = `<p class="meta result-count">${escapeHtml(plural(reports.length, 'report'))} · ${escapeHtml(plural(shotTotal, 'screenshot'))}</p>
      <form method="post" action="/manage/reports/delete" class="manage-form">
        ${hiddenFilters({ ...filters, page })}
        ${bulkBar(reports.length, 'reports', ` (${plural(shotTotal, 'screenshot')})`)}
        <div class="report-list">${cards}</div>
      </form>
      ${pager(filters, page, pages)}`;
    return { html, shots };
  }

  function activityTab(filters, entries) {
    const rows = matchActivity(entries, filters);
    if (!rows.length) return '<p class="empty manage-empty">No activity matches these filters.</p>';
    const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
    const page = Math.min(filters.page, pages);
    const slice = rows.slice((page - 1) * ROWS_PER_PAGE, page * ROWS_PER_PAGE);
    const body = slice.map((entry) => {
      const detail = h.activityDetail(entry);
      return `<tr>
        <td class="pick">${entry.id ? `<input type="checkbox" name="ids" value="${escapeHtml(entry.id)}" data-row aria-label="Select this record" />` : ''}</td>
        <td class="when">${escapeHtml(formatWhen(entry.at))}</td>
        <td>${escapeHtml(entry.email || 'No email')}</td>
        <td><strong>${escapeHtml(h.activityText(entry))}</strong>${detail ? `<span class="meta">${escapeHtml(detail)}</span>` : ''}</td>
      </tr>`;
    }).join('');
    return `<p class="meta result-count">${escapeHtml(plural(rows.length, 'activity record'))}</p>
      <form method="post" action="/manage/activity/delete" class="manage-form">
        ${hiddenFilters({ ...filters, page })}
        ${bulkBar(rows.length, 'activity records')}
        <div class="table-wrap"><table class="manage-table">
          <thead><tr><th class="pick"><span class="sr-only">Select</span></th><th>When</th><th>Email</th><th>What happened</th></tr></thead>
          <tbody>${body}</tbody>
        </table></div>
      </form>
      ${pager(filters, page, pages)}`;
  }

  function alertsTab(filters, alerts) {
    const rows = matchAlerts(alerts, filters);
    if (!rows.length) return '<p class="empty manage-empty">No alerts match these filters.</p>';
    const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
    const page = Math.min(filters.page, pages);
    const slice = rows.slice((page - 1) * ROWS_PER_PAGE, page * ROWS_PER_PAGE);
    const body = slice.map((alert) => `<tr>
        <td class="pick"><input type="checkbox" name="ids" value="${escapeHtml(alert.id)}" data-row aria-label="Select this alert" /></td>
        <td class="when">${escapeHtml(formatWhen(alert.at))}</td>
        <td>${escapeHtml(alert.email || 'No email')}<span class="meta">${escapeHtml(alert.hostname || '')}</span></td>
        <td>${escapeHtml(alert.message || 'Alert')}</td>
        <td>${alert.dismissed ? '<span class="mark">Dismissed</span>' : '<span class="mark alert">Open</span>'}</td>
      </tr>`).join('');
    return `<p class="meta result-count">${escapeHtml(plural(rows.length, 'alert'))}. Deleting an alert keeps its screenshot; remove that on the Screenshots tab.</p>
      <form method="post" action="/manage/alerts/delete" class="manage-form">
        ${hiddenFilters({ ...filters, page })}
        ${bulkBar(rows.length, 'alerts')}
        <div class="table-wrap"><table class="manage-table">
          <thead><tr><th class="pick"><span class="sr-only">Select</span></th><th>When</th><th>Email</th><th>Alert</th><th>Status</th></tr></thead>
          <tbody>${body}</tbody>
        </table></div>
      </form>
      ${pager(filters, page, pages)}`;
  }

  function cleanupTab(people) {
    const forgetOptions = people.map((person) => {
      const counts = [
        person.reports ? plural(person.reports, 'report') : '',
        person.activity ? plural(person.activity, 'event') : '',
        person.alerts ? plural(person.alerts, 'alert') : ''
      ].filter(Boolean).join(', ');
      return `<option value="${escapeHtml(person.key)}">${escapeHtml(person.label)}${counts ? ` (${escapeHtml(counts)})` : ''}</option>`;
    }).join('');
    return `<div class="cleanup-grid">
      <form method="post" action="/manage/forget" class="panel cleanup-card">
        <h2>Forget one email</h2>
        <p class="meta">Deletes every screenshot, activity record and alert for this email.</p>
        <label>Email
          <select name="email" required>
            <option value="">Choose an email</option>
            ${forgetOptions}
          </select>
        </label>
        <button type="submit" class="danger" data-confirm="Delete every screenshot, activity record and alert for this email? This cannot be undone.">Forget this email</button>
      </form>
      <form method="post" action="/manage/cleanup" class="panel cleanup-card">
        <h2>Delete old records</h2>
        <p class="meta">Removes records older than the age you pick, for every email.</p>
        <label>What
          <select name="what">${options(CLEANUP_WHAT, 'shots')}</select>
        </label>
        <label>Older than
          <select name="age">${options(CLEANUP_AGE, '30')}</select>
        </label>
        <button type="submit" class="danger" data-confirm="Delete these old records for every email? This cannot be undone.">Delete old records</button>
      </form>
    </div>`;
  }

  const style = `<style>
    .manage { max-width: 1280px; margin: 0 auto; }
    .manage-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px; margin-bottom: 12px; }
    .manage-head h1 { margin-right: auto; }
    .manage .stat-row p strong { font-variant-numeric: tabular-nums; }
    .manage-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line); margin: 0 0 12px; overflow-x: auto; }
    .manage-tabs a { padding: 10px 14px; color: var(--muted); font-weight: 600; text-decoration: none; border-bottom: 2px solid transparent; white-space: nowrap; }
    .manage-tabs a[aria-current="page"] { color: var(--ink); border-bottom-color: var(--accent); }
    .manage-tabs a:hover { color: var(--ink); }
    .manage-filters { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 8px; margin: 0 0 12px; }
    .manage-filters label, .cleanup-card label { display: flex; flex-direction: column; gap: 4px; margin: 0; font-size: 13px; }
    .manage-filters select, .cleanup-card select {
      min-height: 38px; min-width: 180px; padding: 6px 10px; border: 1px solid var(--line); border-radius: 8px;
      background: #fff; color: var(--ink); font: inherit; font-size: 14px; max-width: 100%;
    }
    .manage-filters .ghost { min-height: 38px; display: inline-flex; align-items: center; text-decoration: none; }
    .result-count { margin: 0 0 8px !important; }
    .bulk-bar {
      display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; padding: 8px 12px; margin: 0 0 12px;
      background: var(--surface); border: 1px solid var(--line); border-radius: 8px; position: sticky; top: 64px; z-index: 5;
    }
    .bulk-bar [data-selected-count] { margin-right: auto; font-variant-numeric: tabular-nums; }
    label.check { display: inline-flex; align-items: center; gap: 8px; margin: 0; color: var(--ink); font-size: 14px; cursor: pointer; }
    label.check input, td.pick input { width: 18px; height: 18px; margin: 0; cursor: pointer; }
    .manage button.danger { background: #b42318; color: #fff; }
    .manage button.danger:hover { background: #912018; }
    .manage button.danger:disabled { background: #eef1f4; color: var(--muted); }
    .manage button.danger-outline { background: #fff; color: #b42318; border: 1px solid #f5c2c0; }
    .manage button.danger-outline:hover { background: #fdecea; }
    .manage button.link-danger { background: transparent; color: #b42318; min-height: 28px; padding: 2px 6px; font-size: 13px; font-weight: 600; }
    .manage button.link-danger:hover { background: #fdecea; }
    .report-list { display: flex; flex-direction: column; gap: 8px; }
    .report-card { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
    .report-card:has([data-row]:checked) { border-color: #b42318; background: #fff8f7; }
    .report-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .report-card > .meta { margin: 4px 0 0; }
    .report-msg { margin: 6px 0 0; font-size: 14px; overflow-wrap: anywhere; }
    .report-shots { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; margin-top: 10px; }
    .mshot { margin: 0; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #fff; }
    .mshot button.thumb { border-radius: 0; }
    .mshot figcaption { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 4px 4px 4px 8px; font-size: 12px; color: var(--muted); }
    .table-wrap { overflow-x: auto; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; }
    .manage-table { width: 100%; border-collapse: collapse; font-size: 14px; }
    .manage-table th { text-align: left; font-size: 12px; color: var(--muted); font-weight: 600; padding: 8px 12px; border-bottom: 1px solid var(--line); background: #f7f8fa; }
    .manage-table td { padding: 8px 12px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
    .manage-table tr:last-child td { border-bottom: 0; }
    .manage-table tr:has([data-row]:checked) td { background: #fff8f7; }
    .manage-table td .meta { display: block; font-size: 12px; margin-top: 2px; }
    .manage-table .pick { width: 40px; }
    .manage-table .when { white-space: nowrap; font-variant-numeric: tabular-nums; color: var(--muted); }
    .pager { display: flex; align-items: center; justify-content: center; gap: 12px; margin: 12px 0 0; }
    .pager .ghost { text-decoration: none; }
    .pager .is-off { opacity: 0.5; cursor: default; }
    .manage-empty { padding: 32px 16px; text-align: center; background: var(--surface); border: 1px dashed var(--line); border-radius: 8px; }
    .cleanup-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(300px, 100%), 1fr)); gap: 12px; }
    .cleanup-card select { width: 100%; min-width: 0; }
    .cleanup-card { min-width: 0; }
    .cleanup-card { display: flex; flex-direction: column; gap: 12px; }
    .cleanup-card .meta { margin: 0; }
    .cleanup-card button { align-self: flex-start; }
    .ok-banner { background: #e7f6ee; border-color: #b7e1c8; color: var(--ok); }
    .warn-banner { background: #fdecea; border-color: #f5c2c0; color: #7a271a; }
    .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
    @media (max-width: 600px) {
      .manage-filters label, .manage-filters select { width: 100%; }
      .bulk-bar { position: static; }
      .report-shots { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
    }
  </style>`;

  const script = `<script>
    (function () {
      document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-confirm]');
        if (button && !window.confirm(button.getAttribute('data-confirm'))) event.preventDefault();
      });
      document.querySelectorAll('form.manage-form').forEach(function (form) {
        var all = form.querySelector('[data-select-all]');
        var count = form.querySelector('[data-selected-count]');
        var needs = form.querySelectorAll('[data-needs-selection]');
        function rows() { return Array.prototype.slice.call(form.querySelectorAll('[data-row]')); }
        function update() {
          var list = rows();
          var picked = list.filter(function (box) { return box.checked; }).length;
          if (count) count.textContent = picked + ' selected';
          needs.forEach(function (button) { button.disabled = picked === 0; });
          if (all) {
            all.checked = list.length > 0 && picked === list.length;
            all.indeterminate = picked > 0 && picked < list.length;
          }
        }
        if (all) all.addEventListener('change', function () {
          rows().forEach(function (box) { box.checked = all.checked; });
          update();
        });
        form.addEventListener('change', function (event) {
          if (event.target.hasAttribute('data-row')) update();
        });
        update();
      });
      var filters = document.getElementById('manage-filters');
      if (filters) filters.addEventListener('change', function () { filters.submit(); });
      if (/[?&]done=1|[?&]err=1/.test(location.search)) {
        var params = new URLSearchParams(location.search);
        ['done', 'err', 'r', 's', 'a', 'l'].forEach(function (key) { params.delete(key); });
        var query = params.toString();
        history.replaceState(null, '', location.pathname + (query ? '?' + query : ''));
      }
    })();
  </script>`;

  function managePage(query) {
    const filters = readFilters(query);
    const reports = h.listReports();
    const entries = h.loadActivity();
    const alerts = h.loadAlerts();
    const people = emailOptions(reports, entries, alerts);
    const disk = storageStats(reports);
    let content = '';
    let galleries = { view: [] };
    if (filters.tab === 'shots') {
      const part = shotsTab(filters);
      content = part.html;
      galleries = { view: part.shots };
    } else if (filters.tab === 'activity') {
      content = activityTab(filters, entries);
    } else if (filters.tab === 'alerts') {
      content = alertsTab(filters, alerts);
    } else {
      content = cleanupTab(people);
    }
    // Email and date carry across tabs; the per-tab filters do not.
    const tabs = TABS.map((tab) => {
      const href = tab.key === 'cleanup'
        ? '/manage?tab=cleanup'
        : `/manage${queryString({ tab: tab.key, email: filters.email, range: filters.range })}`;
      return `<a href="${href}"${tab.key === filters.tab ? ' aria-current="page"' : ''}>${tab.label}</a>`;
    }).join('');
    const openAlerts = alerts.filter((alert) => !alert.dismissed).length;
    const body = `${style}<div class="manage">
      ${doneBanner(query)}
      <div class="manage-head">
        <h1>Manage records</h1>
        <a class="back" href="/">Back to all apps</a>
      </div>
      <div class="stat-row" aria-label="Storage">
        <p><strong>${reports.length}</strong> screenshot report${reports.length === 1 ? '' : 's'}</p>
        <p><strong>${disk.shots}</strong> screenshot${disk.shots === 1 ? '' : 's'} · ${escapeHtml(formatBytes(disk.bytes))}</p>
        <p><strong>${entries.length}</strong> activity record${entries.length === 1 ? '' : 's'}</p>
        <p><strong>${alerts.length}</strong> alert${alerts.length === 1 ? '' : 's'} · ${openAlerts} open</p>
      </div>
      <nav class="manage-tabs" aria-label="Record type">${tabs}</nav>
      ${filters.tab === 'cleanup' ? '' : filterBar(filters, people)}
      ${content}
    </div>${script}`;
    return h.layout('Manage records', body, { galleries, manage: true, subtitle: 'Screenshots and records' });
  }

  function finish(res, filters, counts) {
    const extra = { done: 1, r: counts.r || 0, s: counts.s || 0, a: counts.a || 0, l: counts.l || 0 };
    res.redirect(303, `/manage${queryString(filters, extra)}`);
  }

  function guard(handler) {
    return async (req, res) => {
      if (!h.isAdmin(req)) {
        res.redirect(303, '/');
        return;
      }
      const filters = readFilters(req.body || {});
      try {
        await handler(req, res, filters);
      } catch (err) {
        console.warn('[TRACKINGEYE] Manage delete failed:', err.message);
        res.redirect(303, `/manage${queryString(filters, { err: 1 })}`);
      }
    };
  }

  app.get('/manage', (req, res) => {
    if (!h.isAdmin(req)) {
      res.redirect('/');
      return;
    }
    res.type('html').send(managePage(req.query || {}));
  });

  app.post('/manage/reports/delete', guard(async (req, res, filters) => {
    const ids = req.body?.scope === 'all'
      ? matchReports(filters).map((report) => report.id)
      : idList(req.body?.ids);
    finish(res, filters, deleteReports(ids));
  }));

  app.post('/manage/screenshots/remove', guard(async (req, res, filters) => {
    finish(res, filters, removeShot(req.body?.shot));
  }));

  app.post('/manage/activity/delete', guard(async (req, res, filters) => {
    let a = 0;
    if (req.body?.scope === 'all') {
      const test = (entry) => matchActivity([entry], filters).length === 1;
      a = await deleteActivity(test);
    } else {
      const ids = new Set(idList(req.body?.ids));
      if (ids.size) a = await deleteActivity((entry) => ids.has(String(entry.id)));
    }
    finish(res, filters, { a });
  }));

  app.post('/manage/alerts/delete', guard(async (req, res, filters) => {
    let l = 0;
    if (req.body?.scope === 'all') {
      l = deleteAlerts((alert) => matchAlerts([alert], filters).length === 1);
    } else {
      const ids = new Set(idList(req.body?.ids));
      if (ids.size) l = deleteAlerts((alert) => ids.has(String(alert.id)));
    }
    finish(res, filters, { l });
  }));

  app.post('/manage/forget', guard(async (req, res) => {
    const back = readFilters({ tab: 'cleanup' });
    const raw = String(req.body?.email || '').trim();
    const key = raw === '__none__' ? '__none__' : emailKey(raw);
    if (!key) {
      finish(res, back, {});
      return;
    }
    const counts = deleteReports(h.listReports().filter((report) => sameEmail(report.email, key)).map((report) => report.id));
    counts.a = await deleteActivity((entry) => sameEmail(entry.email, key));
    counts.l = deleteAlerts((alert) => sameEmail(alert.email, key));
    finish(res, back, counts);
  }));

  app.post('/manage/cleanup', guard(async (req, res) => {
    const back = readFilters({ tab: 'cleanup' });
    const what = pick(req.body?.what, CLEANUP_WHAT) || 'shots';
    const age = pick(req.body?.age, CLEANUP_AGE) || '30';
    const range = `older${age}`;
    let counts = {};
    if (what === 'shots' || what === 'all') {
      counts = deleteReports(h.listReports().filter((report) => inRange(report.createdAt, range)).map((report) => report.id));
    }
    if (what === 'activity' || what === 'all') counts.a = await deleteActivity((entry) => inRange(entry.at, range));
    if (what === 'alerts' || what === 'all') counts.l = deleteAlerts((alert) => inRange(alert.at, range));
    finish(res, back, counts);
  }));
};
