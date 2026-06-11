package server

// dashboardTemplate is the status page. It is fully self-contained: system font
// stack, inline CSS/JS, inline SVG favicon — no external resources, so it works
// air-gapped and keeps the CSP free of third-party origins. Without JavaScript
// the page degrades to the server-rendered table refreshed via <noscript> meta
// refresh; with JavaScript it polls /api/tunnels and updates in place.
const dashboardTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sottopasso &mdash; Dashboard</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cpath d='M10 50 Q 20 20, 50 30 T 90 50 M10 50 Q 20 80, 50 70 T 90 50' fill='none' stroke='%234f8cff' stroke-width='10' stroke-linecap='round'/%3E%3C/svg%3E">
    <noscript><meta http-equiv="refresh" content="5"></noscript>
    <style>
        :root {
            --bg: #14161a;
            --panel: #1d2026;
            --panel-2: #23262d;
            --text: #e6e8eb;
            --muted: #9aa3ad;
            --border: #2e333b;
            --accent: #4f8cff;
            --ok: #34c759;
            --danger: #e5484d;
            --danger-hover: #c93a3f;
            --shadow: 0 1px 3px rgba(0,0,0,.35);
        }
        body.light-mode {
            --bg: #f4f5f7;
            --panel: #ffffff;
            --panel-2: #eef0f3;
            --text: #1c1e21;
            --muted: #5c6670;
            --border: #dde0e5;
            --shadow: 0 1px 3px rgba(0,0,0,.08);
        }
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 1.5rem;
            transition: background-color .25s, color .25s;
        }
        .mono { font-family: ui-monospace, SFMono-Regular, "Cascadia Mono", Consolas, Menlo, monospace; font-size: .85rem; }
        .muted { color: var(--muted); }
        .container { max-width: 1200px; margin: 0 auto; }

        .header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
        .header-left { display: flex; align-items: center; gap: .75rem; }
        .logo { width: 36px; height: 36px; }
        h1 { font-size: 1.5rem; font-weight: 650; margin: 0; letter-spacing: -.01em; }

        .theme-switch { display: inline-block; height: 26px; position: relative; width: 48px; }
        .theme-switch input { display: none; }
        .slider { background: var(--panel-2); border: 1px solid var(--border); position: absolute; inset: 0; cursor: pointer; transition: .3s; border-radius: 26px; }
        .slider:before { background: var(--muted); content: ""; height: 18px; width: 18px; position: absolute; left: 3px; top: 3px; transition: .3s; border-radius: 50%; }
        input:checked + .slider { background: var(--accent); border-color: var(--accent); }
        input:checked + .slider:before { background: #fff; transform: translateX(22px); }

        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; margin-bottom: 1.25rem; }
        .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: .8rem 1rem; box-shadow: var(--shadow); }
        .card-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: .3rem; }
        .card-value { font-size: 1.35rem; font-weight: 650; font-variant-numeric: tabular-nums; }

        .toolbar { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
        #filter {
            flex: 1; min-width: 200px; max-width: 360px;
            background: var(--panel); color: var(--text);
            border: 1px solid var(--border); border-radius: 8px;
            padding: .55rem .8rem; font-size: .9rem; outline: none;
        }
        #filter:focus { border-color: var(--accent); }
        .auto { display: flex; align-items: center; gap: .4rem; font-size: .85rem; color: var(--muted); cursor: pointer; user-select: none; }
        #updated { font-size: .8rem; margin-left: auto; }
        #updated.error { color: var(--danger); }

        .table-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: .7rem .9rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
        th { background: var(--panel-2); font-weight: 600; text-transform: uppercase; font-size: .72rem; letter-spacing: .06em; color: var(--muted); white-space: nowrap; }
        tbody tr:last-child td { border-bottom: none; }
        tbody tr:hover td { background: var(--panel-2); }
        .url { word-break: break-all; }
        .url a { color: var(--accent); text-decoration: none; }
        .url a:hover { text-decoration: underline; }

        .badge { display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
        .badge-http { background: rgba(79,140,255,.15); color: var(--accent); }
        .badge-tcp { background: rgba(52,199,89,.15); color: var(--ok); }

        .status { display: inline-flex; align-items: center; gap: .4rem; font-weight: 600; font-size: .85rem; }
        .status .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
        .status-active .dot { background: var(--ok); box-shadow: 0 0 0 3px rgba(52,199,89,.18); }
        .uptime, .traffic { font-variant-numeric: tabular-nums; white-space: nowrap; }

        .copy-btn {
            background: none; border: 1px solid var(--border); color: var(--muted);
            border-radius: 6px; cursor: pointer; padding: .15rem .45rem; margin-left: .4rem;
            font-size: .8rem; line-height: 1.2; vertical-align: middle;
        }
        .copy-btn:hover { color: var(--text); border-color: var(--muted); }

        .action-button {
            background: var(--danger); color: #fff; border: none;
            padding: .45rem .9rem; border-radius: 7px; cursor: pointer; font-size: .82rem; font-weight: 600;
        }
        .action-button:hover { background: var(--danger-hover); }

        .empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }

        @media (max-width: 768px) {
            body { padding: .75rem; }
            #updated { margin-left: 0; }
            .table-wrap { overflow-x: visible; border: none; background: none; box-shadow: none; }
            table, thead, tbody, th, td, tr { display: block; }
            thead { display: none; }
            tbody tr { border: 1px solid var(--border); margin-bottom: .8rem; border-radius: 10px; background: var(--panel); box-shadow: var(--shadow); overflow: hidden; }
            tbody tr:hover td { background: none; }
            td { border: none; border-bottom: 1px solid var(--border); position: relative; padding: .6rem .8rem .6rem 42%; min-height: 1.2rem; }
            tr td:last-child { border-bottom: none; }
            td:before {
                position: absolute; top: 50%; transform: translateY(-50%); left: .8rem; width: 38%;
                white-space: nowrap; font-weight: 600; text-transform: uppercase; font-size: .68rem; color: var(--muted);
            }
            td:nth-of-type(1):before { content: "ID"; }
            td:nth-of-type(2):before { content: "Type"; }
            td:nth-of-type(3):before { content: "Public URL"; }
            td:nth-of-type(4):before { content: "Client"; }
            td:nth-of-type(5):before { content: "Status"; }
            td:nth-of-type(6):before { content: "Uptime"; }
            td:nth-of-type(7):before { content: "In / Out"; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:var(--accent);stop-opacity:1" />
                            <stop offset="100%" style="stop-color:var(--ok);stop-opacity:1" />
                        </linearGradient>
                    </defs>
                    <path d="M10 50 Q 20 20, 50 30 T 90 50 M10 50 Q 20 80, 50 70 T 90 50" fill="none" stroke="url(#logoGradient)" stroke-width="10" stroke-linecap="round"/>
                </svg>
                <h1>Sottopasso</h1>
            </div>
            <label class="theme-switch" for="theme-checkbox" title="Toggle light/dark theme">
                <input type="checkbox" id="theme-checkbox" />
                <div class="slider"></div>
            </label>
        </div>

        <div class="stats">
            <div class="card"><div class="card-label">Active tunnels</div><div class="card-value" id="stat-active">{{ len . }}</div></div>
            <div class="card"><div class="card-label">HTTP</div><div class="card-value" id="stat-http">{{ countType . "http" }}</div></div>
            <div class="card"><div class="card-label">TCP</div><div class="card-value" id="stat-tcp">{{ countType . "tcp" }}</div></div>
            <div class="card"><div class="card-label">Traffic in</div><div class="card-value" id="stat-in">{{ formatBytes (totalIn .) }}</div></div>
            <div class="card"><div class="card-label">Traffic out</div><div class="card-value" id="stat-out">{{ formatBytes (totalOut .) }}</div></div>
        </div>

        <div class="toolbar">
            <input type="search" id="filter" placeholder="Filter by ID, URL, client&hellip;" autocomplete="off">
            <label class="auto"><input type="checkbox" id="autorefresh" checked> Auto-refresh</label>
            <span id="updated" class="muted"></span>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Public URL</th>
                        <th>Client</th>
                        <th>Status</th>
                        <th>Uptime</th>
                        <th>Traffic (In / Out)</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody id="tunnels-body">
                    {{range .}}
                    <tr>
                        <td class="mono" title="{{ .ID }}">{{ printf "%.8s" .ID }}</td>
                        <td><span class="badge badge-{{ .Type }}">{{ .Type }}</span></td>
                        <td class="url">{{ if isHTTPURL .PublicURL }}<a href="{{ .PublicURL }}" target="_blank" rel="noopener noreferrer">{{ .PublicURL }}</a>{{ else }}<span class="mono">{{ .PublicURL }}</span>{{ end }}<button type="button" class="copy-btn" data-copy="{{ .PublicURL }}" title="Copy URL">&#10697;</button></td>
                        <td class="mono">{{ .ClientAddr }}</td>
                        <td><span class="status status-{{ .Status }}"><span class="dot"></span>{{ .Status }}</span></td>
                        <td class="uptime" data-uptime="{{ uptimeSeconds .CreatedAt }}" title="Created {{ .CreatedAt.Format "2006-01-02 15:04:05" }}">{{ duration .CreatedAt }}</td>
                        <td class="traffic">{{ formatBytes .TotalBytesIn.Load }} / {{ formatBytes .TotalBytesOut.Load }}</td>
                        <td>
                            <form method="POST" action="/" class="close-form" data-id="{{ .ID }}" style="margin:0;">
                                <input type="hidden" name="csrf_token" value="{{ csrfToken }}">
                                <input type="hidden" name="tunnelId" value="{{ .ID }}">
                                <button type="submit" class="action-button">Close</button>
                            </form>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            <div id="empty" class="empty" {{ if . }}hidden{{ end }}>No active tunnels.</div>
        </div>
    </div>

    <script>
        "use strict";
        var CSRF_TOKEN = "{{ csrfToken }}";
        var POLL_MS = 5000;

        /* ---- theme ---- */
        var themeToggle = document.getElementById('theme-checkbox');
        (function () {
            var saved = localStorage.getItem('theme');
            var light = saved === 'light-mode' ||
                (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
            if (light) document.body.classList.add('light-mode');
            themeToggle.checked = light;
        })();
        themeToggle.addEventListener('change', function () {
            document.body.classList.toggle('light-mode', themeToggle.checked);
            localStorage.setItem('theme', themeToggle.checked ? 'light-mode' : 'dark-mode');
        });

        /* ---- formatting (mirrors the Go template funcs) ---- */
        function fmtBytes(b) {
            var unit = 1024;
            if (b < unit) return b + ' B';
            var v = b / unit, suffixes = ['KB', 'MB', 'GB', 'TB'];
            for (var i = 0; i < suffixes.length; i++) {
                if (v < unit || i === suffixes.length - 1) return v.toFixed(2) + ' ' + suffixes[i];
                v /= unit;
            }
        }
        function fmtDuration(totalSeconds) {
            var s = Math.max(0, Math.floor(totalSeconds));
            var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
            var out = '';
            if (h) out += h + 'h';
            if (h || m) out += m + 'm';
            return out + sec + 's';
        }

        /* ---- state + rendering ---- */
        var tunnels = null;            // last JSON payload (null until first fetch)
        var fetchedAt = Date.now();    // when that payload was received
        var tbody = document.getElementById('tunnels-body');
        var emptyEl = document.getElementById('empty');
        var filterEl = document.getElementById('filter');
        var updatedEl = document.getElementById('updated');

        function el(tag, className, text) {
            var node = document.createElement(tag);
            if (className) node.className = className;
            if (text !== undefined) node.textContent = text;
            return node;
        }

        function buildRow(t) {
            var tr = document.createElement('tr');

            var tdID = el('td', 'mono', t.id.slice(0, 8));
            tdID.title = t.id;
            tr.appendChild(tdID);

            var tdType = el('td');
            tdType.appendChild(el('span', 'badge badge-' + t.type, t.type));
            tr.appendChild(tdType);

            var tdURL = el('td', 'url');
            if (/^https?:\/\//.test(t.public_url)) {
                var a = el('a', '', t.public_url);
                a.href = t.public_url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                tdURL.appendChild(a);
            } else {
                tdURL.appendChild(el('span', 'mono', t.public_url));
            }
            var copy = el('button', 'copy-btn', '⧉');
            copy.type = 'button';
            copy.title = 'Copy URL';
            copy.setAttribute('data-copy', t.public_url);
            tdURL.appendChild(copy);
            tr.appendChild(tdURL);

            tr.appendChild(el('td', 'mono', t.client_addr));

            var tdStatus = el('td');
            var status = el('span', 'status status-' + t.status);
            status.appendChild(el('span', 'dot'));
            status.appendChild(document.createTextNode(t.status));
            tdStatus.appendChild(status);
            tr.appendChild(tdStatus);

            var tdUptime = el('td', 'uptime', fmtDuration(t.uptime_seconds));
            tdUptime.setAttribute('data-uptime', t.uptime_seconds);
            tdUptime.title = 'Created ' + new Date(t.created_at).toLocaleString();
            tr.appendChild(tdUptime);

            tr.appendChild(el('td', 'traffic', fmtBytes(t.bytes_in) + ' / ' + fmtBytes(t.bytes_out)));

            var tdAction = el('td');
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/';
            form.className = 'close-form';
            form.style.margin = '0';
            form.setAttribute('data-id', t.id);
            var csrf = document.createElement('input');
            csrf.type = 'hidden'; csrf.name = 'csrf_token'; csrf.value = CSRF_TOKEN;
            var tid = document.createElement('input');
            tid.type = 'hidden'; tid.name = 'tunnelId'; tid.value = t.id;
            var btn = el('button', 'action-button', 'Close');
            btn.type = 'submit';
            form.appendChild(csrf); form.appendChild(tid); form.appendChild(btn);
            tdAction.appendChild(form);
            tr.appendChild(tdAction);

            return tr;
        }

        function render() {
            if (tunnels === null) return; // keep the server-rendered table until the first fetch
            var filter = filterEl.value.trim().toLowerCase();
            tbody.textContent = '';
            var shown = 0;
            var totalIn = 0, totalOut = 0, http = 0, tcp = 0;
            tunnels.forEach(function (t) {
                totalIn += t.bytes_in; totalOut += t.bytes_out;
                if (t.type === 'http') http++; else if (t.type === 'tcp') tcp++;
                var hay = (t.id + ' ' + t.type + ' ' + t.public_url + ' ' + t.client_addr).toLowerCase();
                if (filter && hay.indexOf(filter) === -1) return;
                shown++;
                tbody.appendChild(buildRow(t));
            });
            emptyEl.hidden = shown !== 0;
            emptyEl.textContent = tunnels.length === 0 ? 'No active tunnels.' : 'No tunnels match the filter.';
            document.getElementById('stat-active').textContent = tunnels.length;
            document.getElementById('stat-http').textContent = http;
            document.getElementById('stat-tcp').textContent = tcp;
            document.getElementById('stat-in').textContent = fmtBytes(totalIn);
            document.getElementById('stat-out').textContent = fmtBytes(totalOut);
        }

        /* ---- polling ---- */
        function refresh() {
            fetch('/api/tunnels', { headers: { 'Accept': 'application/json' }, cache: 'no-store' })
                .then(function (res) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function (data) {
                    tunnels = data.tunnels || [];
                    fetchedAt = Date.now();
                    render();
                    updatedEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
                    updatedEl.classList.remove('error');
                })
                .catch(function () {
                    updatedEl.textContent = 'Update failed — retrying…';
                    updatedEl.classList.add('error');
                });
        }

        var pollTimer = null;
        var autoEl = document.getElementById('autorefresh');
        function setPolling(on) {
            if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
            if (on) pollTimer = setInterval(refresh, POLL_MS);
        }
        autoEl.addEventListener('change', function () {
            setPolling(autoEl.checked && !document.hidden);
        });
        document.addEventListener('visibilitychange', function () {
            setPolling(autoEl.checked && !document.hidden);
            if (!document.hidden && autoEl.checked) refresh();
        });

        filterEl.addEventListener('input', render);

        /* confirm before closing a tunnel (delegated: covers JS-rendered rows) */
        document.addEventListener('submit', function (e) {
            var form = e.target;
            if (form.classList.contains('close-form') &&
                !confirm('Close tunnel ' + (form.getAttribute('data-id') || '').slice(0, 8) + '? The public endpoint stops immediately.')) {
                e.preventDefault();
            }
        });

        /* copy-to-clipboard (delegated) */
        document.addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('.copy-btn') : null;
            if (!btn) return;
            var text = btn.getAttribute('data-copy') || '';
            var flash = function (ok) {
                btn.textContent = ok ? '✓' : '✗';
                setTimeout(function () { btn.textContent = '⧉'; }, 1200);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () { flash(true); }, function () { flash(false); });
            } else {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed'; ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                var ok = false;
                try { ok = document.execCommand('copy'); } catch (err) { /* ignore */ }
                document.body.removeChild(ta);
                flash(ok);
            }
        });

        /* tick uptimes locally between polls (skew-free: server base + local elapsed) */
        setInterval(function () {
            var extra = Math.floor((Date.now() - fetchedAt) / 1000);
            var cells = tbody.querySelectorAll('.uptime');
            for (var i = 0; i < cells.length; i++) {
                var base = parseInt(cells[i].getAttribute('data-uptime'), 10);
                if (!isNaN(base)) cells[i].textContent = fmtDuration(base + extra);
            }
        }, 1000);

        setPolling(true);
        refresh();
    </script>
</body>
</html>
`
