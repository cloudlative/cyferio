// Shared helpers used by every page's inline <script> block.

// --- Site-wide top loading bar, driven automatically by apiFetch() -------
let _pendingRequests = 0;

function _progressStart() {
	_pendingRequests++;
	const spinner = document.getElementById("page-progress");
	if (!spinner || _pendingRequests !== 1) return;
	spinner.classList.add("active");
}

function _progressDone() {
	_pendingRequests = Math.max(0, _pendingRequests - 1);
	const spinner = document.getElementById("page-progress");
	if (!spinner || _pendingRequests !== 0) return;
	spinner.classList.remove("active");
}

/**
 * Shows a toast notification. Auto-dismisses after
 * window.NOTIFICATION_DURATION_MS (admin-configurable via Settings ->
 * Notifications, set on `window` by base.html from the cached `runtime`
 * settings value -- see app_settings.py; defaults to 1000ms/1s if that
 * global is somehow unset, e.g. a page that doesn't extend base.html), or
 * immediately via its "×" close button. Multiple toasts stack (newest at
 * the bottom, pushing older ones up) rather than replacing each other.
 *
 * If a native <dialog> is currently open, the toast is appended inside that
 * dialog instead of document.body: a <dialog> creates its own top-layer
 * stacking context that no z-index on a body-level element can render
 * above, so a toast fired while e.g. the edit-user dialog is open would
 * otherwise be stuck invisibly behind it.
 */
function toast(message, kind = "success") {
	const openDialog = document.querySelector("dialog[open]");
	let container = openDialog
		? openDialog.querySelector(":scope > #toast-container")
		: document.getElementById("toast-container");
	if (openDialog && !container) {
		container = document.createElement("div");
		container.id = "toast-container";
		openDialog.appendChild(container);
	}

	const el = document.createElement("div");
	el.className = `toast ${kind}`;
	const text = document.createElement("span");
	text.textContent = message;
	el.appendChild(text);
	const closeBtn = document.createElement("button");
	closeBtn.type = "button";
	closeBtn.className = "toast-close";
	closeBtn.setAttribute("aria-label", "Dismiss");
	closeBtn.textContent = "×";
	closeBtn.addEventListener("click", () => el.remove());
	el.appendChild(closeBtn);

	container.appendChild(el);
	const duration = Number(window.NOTIFICATION_DURATION_MS) || 1000;
	setTimeout(() => el.remove(), duration);
}

/**
 * Wrapper around fetch() for the JSON API: throws a readable Error on any
 * non-2xx response (using the API's {"detail": "..."} message when
 * present), and redirects to /login if the session has expired.
 */
async function apiFetch(url, options = {}) {
	const opts = { ...options };
	if (opts.body && typeof opts.body !== "string") {
		opts.headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
		opts.body = JSON.stringify(opts.body);
	}
	_progressStart();
	try {
		const res = await fetch(url, opts);
		if (res.status === 401) {
			window.location.href = "/login";
			throw new Error("Session expired");
		}
		if (!res.ok) {
			let detail = `Request failed (${res.status})`;
			try {
				const data = await res.json();
				if (data && data.detail) detail = data.detail;
			} catch (_) { /* body wasn't JSON */ }
			throw new Error(detail);
		}
		if (res.status === 204) return null;
		return await res.json();
	} finally {
		_progressDone();
	}
}

/**
 * Same contract as apiFetch above, for a multipart/form-data POST (the
 * Support Ticketing System's create/reply endpoints, which take Form()
 * fields -- and, once attachments ship, File uploads -- rather than a
 * JSON body). Deliberately NOT folded into apiFetch itself: that
 * function's "JSON-encode any non-string body" branch would otherwise
 * mis-encode a FormData object and clobber its multipart Content-Type
 * boundary header.
 */
async function apiFetchForm(url, formData, options = {}) {
	_progressStart();
	try {
		const res = await fetch(url, { method: "POST", ...options, body: formData });
		if (res.status === 401) {
			window.location.href = "/login";
			throw new Error("Session expired");
		}
		if (!res.ok) {
			let detail = `Request failed (${res.status})`;
			try {
				const data = await res.json();
				if (data && data.detail) detail = data.detail;
			} catch (_) { /* body wasn't JSON */ }
			throw new Error(detail);
		}
		if (res.status === 204) return null;
		return await res.json();
	} finally {
		_progressDone();
	}
}

/**
 * Shows a native <dialog> confirm prompt and resolves true/false. Used for
 * anything destructive (revoke client, delete user) so a non-technical user
 * never triggers it by a stray click alone.
 */
function confirmDialog(message, { confirmLabel = "Confirm", danger = true } = {}) {
	return new Promise((resolve) => {
		const dlg = document.createElement("dialog");
		dlg.innerHTML = `
			<div class="dialog-body">
				<p>${message}</p>
				<div class="dialog-actions">
					<button class="btn-secondary" data-action="cancel">Cancel</button>
					<button class="${danger ? "btn-danger" : "btn-primary"}" data-action="confirm">${confirmLabel}</button>
				</div>
			</div>`;
		document.body.appendChild(dlg);
		dlg.addEventListener("close", () => {
			resolve(dlg.returnValue === "confirm");
			dlg.remove();
		});
		dlg.querySelector('[data-action="cancel"]').onclick = () => dlg.close("cancel");
		dlg.querySelector('[data-action="confirm"]').onclick = () => dlg.close("confirm");
		dlg.showModal();
	});
}

/**
 * Step-up-auth password prompt -- a masked (with the same show/hide toggle
 * every other password field on this app gets, see addPasswordToggle
 * above), real `<dialog>`, replacing the browser's native `prompt()`.
 * `prompt()` has three real problems for a password: no `type="password"`
 * masking exists for it (the value is shown in plain text as the person
 * types), it's a blocking, unstyled OS-native dialog most browsers now
 * flag as a legacy/deprecated pattern, and (unlike every other input in
 * this app) it gets zero autocomplete/credential-manager integration.
 * Resolves to the entered password (a non-empty string) on Confirm, or
 * `null` on Cancel/Escape/backdrop-dismiss -- callers already treat a
 * falsy return from the old promptCurrentPassword() as "user backed out",
 * so this is a drop-in replacement for that call shape.
 */
function passwordConfirmDialog(message, { confirmLabel = "Confirm" } = {}) {
	return new Promise((resolve) => {
		const dlg = document.createElement("dialog");
		dlg.innerHTML = `
			<div class="dialog-body">
				<p>${message}</p>
				<div class="field">
					<label for="password-confirm-input">Current Password</label>
					<input type="password" id="password-confirm-input" autocomplete="current-password" autofocus>
				</div>
				<div class="dialog-actions">
					<button class="btn-secondary" data-action="cancel">Cancel</button>
					<button class="btn-primary" data-action="confirm">${confirmLabel}</button>
				</div>
			</div>`;
		document.body.appendChild(dlg);
		const input = dlg.querySelector("#password-confirm-input");
		window.addPasswordToggle(input); // window.-qualified: assigned by a later IIFE in this file (initPasswordToggles), already run by the time a caller actually opens this dialog, but a bare reference here would trip eslint's no-undef (it doesn't track cross-IIFE global assignment)

		let confirmed = false;
		const submit = () => { confirmed = true; dlg.close(); };
		dlg.addEventListener("close", () => {
			resolve(confirmed && input.value ? input.value : null);
			dlg.remove();
		});
		dlg.querySelector('[data-action="cancel"]').onclick = () => dlg.close();
		dlg.querySelector('[data-action="confirm"]').onclick = submit;
		// Enter submits, same as a normal <form> -- this dialog has no
		// <form> of its own (nothing to actually POST here, the resolved
		// password is handed back to the caller's own apiFetch call), so
		// Enter needs its own explicit handler instead of relying on a
		// submit-button-triggered form submission.
		input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") submit(); });
		dlg.showModal();
		input.focus();
	});
}

// A small set of colors reused across every chart on the site, drawn from
// the same accent/status palette already defined in style.css (:root
// custom properties) so charts never introduce a clashing color scheme.
// Fixed categorical order -- never reassigned by data/sort order, so the
// same claimed name/OS always gets the same color across a refresh. This
// is the dataviz skill's validated 8-hue set for a dark card surface
// (blue/orange/aqua/yellow/magenta/green/violet/red): the previous
// 10-color palette failed both the lightness-band and CVD-separation
// checks (several adjacent stops were only ΔE 4.6 apart -- effectively
// indistinguishable to a colorblind viewer, and washed-out/low-contrast
// for everyone else). 8 slots exactly matches renderRejectedChart's own
// "top 8" cap, so nothing here ever needs to cycle past slot 8.
const CHART_COLORS = [
	"#3987e5", "#d95926", "#199e70", "#c98500",
	"#d55181", "#008300", "#9085e9", "#e66767",
];

/**
 * Renders a dependency-free SVG donut chart into `mountEl` from
 * `entries` = [{ label, value }, ...]. No external charting library --
 * this app can't rely on reaching a CDN, and the need here is simple
 * enough not to warrant a new dependency.
 */
function renderDonutChart(mountEl, entries, { size = 220, thickness = 34 } = {}) {
	const total = entries.reduce((sum, e) => sum + e.value, 0);
	if (total === 0 || entries.length === 0) {
		mountEl.innerHTML = '<p class="muted">Nothing to chart yet.</p>';
		return;
	}
	const r = (size - thickness) / 2;
	const cx = size / 2, cy = size / 2;
	const circumference = 2 * Math.PI * r;
	let offset = 0;
	const arcs = entries.map((e, i) => {
		const fraction = e.value / total;
		const dash = fraction * circumference;
		// Rotation to start segments at 12 o'clock comes from CSS
		// (.donut-segment { transform: rotate(-90deg) }), not an SVG
		// "transform" attribute here -- mixing a presentation-attribute
		// transform with the CSS `transition: transform` on this class is
		// a known Chromium paint bug where the segment can silently fail
		// to render after an innerHTML swap until something forces a
		// style recalc. transform-origin is fixed at the shape's own
		// center via CSS custom property since size/cx/cy vary per call.
		const circle = `<circle class="donut-segment" cx="${cx}" cy="${cy}" r="${r}" fill="none"
			stroke="${CHART_COLORS[i % CHART_COLORS.length]}" stroke-width="${thickness}"
			stroke-dasharray="${dash} ${circumference - dash}"
			stroke-dashoffset="${-offset}" style="transform-origin:${cx}px ${cy}px">
			<title>${escapeHtml(e.label)}: ${e.value} (${(fraction * 100).toFixed(1)}%)</title>
		</circle>`;
		offset += dash;
		return circle;
	}).join("");

	// Fixed-width label/count columns (not flex:1) so a legend with only
	// one or two rows doesn't stretch across the full mount width and
	// leave a huge gap between the label and its count -- this mount can
	// be half a wide card (e.g. the Diagnostics rejections breakdown).
	const legend = entries.map((e, i) => `
		<div class="donut-legend-row" style="display:flex;align-items:center;gap:8px;font-size:0.85rem;padding:3px 6px;border-radius:6px;">
			<span style="width:10px;height:10px;border-radius:3px;background:${CHART_COLORS[i % CHART_COLORS.length]};flex:none"></span>
			<span style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(e.label)}</span>
			<span class="muted mono">${e.value} (${Math.round((e.value / total) * 100)}%)</span>
		</div>`).join("");

	mountEl.innerHTML = `
		<div style="display:flex;gap:28px;align-items:center;flex-wrap:wrap">
			<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Donut chart">
				${arcs}
				<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="middle"
					fill="var(--text)" font-size="${size * 0.13}" font-weight="800">${total}</text>
			</svg>
			<div style="display:flex;flex-direction:column;gap:8px">${legend}</div>
		</div>`;
}

/**
 * Dependency-free bar chart, built from plain divs (not SVG -- unlike the
 * donut chart above, bars need no curve geometry, and percentage-height/
 * width flex children are simpler and less error-prone here). Two shapes:
 *
 *   renderBarChart(mount, [{label, value}, ...])
 *     Vertical bars (day/hour x-axis charts, e.g. Sessions Per Day).
 *
 *   renderBarChart(mount, [{label, value}, ...], {horizontal: true})
 *     Ranked horizontal bars (e.g. Top Clients by Data Usage) -- reads
 *     better than vertical bars when comparing a handful of named values.
 *
 *   renderBarChart(mount, [{label, values: [rx, tx]}, ...], {seriesLabels: ["Received", "Sent"]})
 *     Vertical STACKED bars (e.g. Bandwidth Trend's RX+TX per day) -- one
 *     CHART_COLORS slot per series index, stacked bottom-to-top within
 *     each bar, plus a legend row (same visual language as the donut
 *     chart's own legend).
 *
 * `valueFormatter` controls how values are displayed in tooltips/labels
 * (e.g. fmtBytes for byte totals, plain integers for counts).
 */
function renderBarChart(mountEl, entries, {
	horizontal = false, seriesLabels = null, valueFormatter = (v) => String(v), barHeight = 200,
} = {}) {
	const stacked = !!seriesLabels;
	const totals = entries.map(e => stacked ? e.values.reduce((s, v) => s + v, 0) : e.value);
	const max = Math.max(0, ...totals);
	if (entries.length === 0 || max === 0) {
		mountEl.innerHTML = '<p class="muted">Not enough data yet.</p>';
		return;
	}

	const legend = stacked ? `<div style="display:flex;gap:16px;margin-bottom:14px;flex-wrap:wrap">${
		seriesLabels.map((s, i) => `
			<div style="display:flex;align-items:center;gap:8px;font-size:0.85rem">
				<span style="width:10px;height:10px;border-radius:3px;background:${CHART_COLORS[i % CHART_COLORS.length]};flex:none"></span>
				<span class="muted">${escapeHtml(s)}</span>
			</div>`).join("")
	}</div>` : "";

	if (horizontal) {
		const rows = entries.map((e, i) => {
			const pct = Math.max(2, Math.round((e.value / max) * 100)); // 2% floor so a nonzero value is never invisible
			return `
				<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
					<span style="width:110px;flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.85rem" title="${escapeHtml(e.label)}">${escapeHtml(e.label)}</span>
					<div style="flex:1;background:var(--surface-alt);border-radius:5px;height:20px;overflow:hidden">
						<div style="width:${pct}%;height:100%;background:${CHART_COLORS[i % CHART_COLORS.length]};border-radius:5px"></div>
					</div>
					<span class="muted mono" style="width:70px;flex:none;text-align:right;font-size:0.82rem">${escapeHtml(valueFormatter(e.value))}</span>
				</div>`;
		}).join("");
		mountEl.innerHTML = rows;
		return;
	}

	const bars = entries.map(e => {
		const total = stacked ? e.values.reduce((s, v) => s + v, 0) : e.value;
		const totalPx = max > 0 ? Math.max(total > 0 ? 2 : 0, Math.round((total / max) * barHeight)) : 0;
		const segmentsHtml = stacked
			? e.values.map((v, i) => {
				const segPx = total > 0 ? Math.round((v / total) * totalPx) : 0;
				return `<div style="width:100%;height:${segPx}px;background:${CHART_COLORS[i % CHART_COLORS.length]}"><title>${escapeHtml(seriesLabels[i])}: ${escapeHtml(valueFormatter(v))}</title></div>`;
			}).join("")
			: `<div style="width:100%;height:${totalPx}px;background:${CHART_COLORS[0]}"></div>`;
		return `
			<div style="display:flex;flex-direction:column;align-items:center;flex:1;min-width:0">
				<div title="${escapeHtml(e.label)}: ${escapeHtml(valueFormatter(total))}"
					style="width:100%;max-width:34px;height:${barHeight}px;display:flex;flex-direction:column-reverse;border-radius:3px 3px 0 0;overflow:hidden;background:${total === 0 ? "var(--surface-alt)" : "transparent"}">
					${segmentsHtml}
				</div>
				<span class="muted" style="font-size:0.72rem;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%" title="${escapeHtml(e.label)}">${escapeHtml(e.label)}</span>
			</div>`;
	}).join("");

	mountEl.innerHTML = `${legend}<div style="display:flex;align-items:flex-end;gap:6px;overflow-x:auto;padding-bottom:2px">${bars}</div>`;
}

// --- Chart.js-backed charts (Reports -> Analytics) -----------------------
//
// renderBarChart/renderDonutChart above stay exactly as they are (still
// used elsewhere, e.g. Diagnostics' rejection breakdowns) -- these are a
// separate, additive layer for the 5 Usage Analytics charts specifically,
// which need real chart-type switching (bar/line/area/donut/pie/stacked)
// and richer tooltips than a plain div/SVG chart can give cheaply. Backed
// by the vendored Chart.js UMD build (static/vendor/chart.umd.min.js,
// loaded in base.html before this file) -- see that file's own README.md
// for version/provenance.
//
// Known limitation: Chart.js bakes resolved colors into canvas draw calls
// at render time, unlike renderBarChart/renderDonutChart's raw CSS
// var(--...) references (which repaint live on a theme switch for free).
// Switching themes via the header's quick-switch while viewing a Chart.js
// chart does NOT recolor it until the next explicit re-render (e.g.
// clicking Reports' own Refresh button, or a range-selector change) --
// an accepted, documented trade-off for this phase, not a bug.

/**
 * Resolves a CSS custom property to its current computed value (Chart.js
 * draws on a <canvas>, so it needs a literal color string -- it can't
 * understand "var(--text)" the way an SVG/div's `style` attribute can).
 */
function cssVar(name) {
	return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/**
 * Chart.js color helpers built from the same CHART_COLORS palette every
 * other chart in this app uses, so a chart doesn't look like it belongs to
 * a different product depending on which rendering path drew it.
 */
const CHART_JS_PALETTE = {
	line: (i) => CHART_COLORS[i % CHART_COLORS.length],
	fill: (i, alpha = 0.55) => {
		const hex = CHART_COLORS[i % CHART_COLORS.length];
		const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
		return `rgba(${r}, ${g}, ${b}, ${alpha})`;
	},
};

// One Chart.js instance per <canvas>, so a chart-type switch or a range
// change can safely re-render into the same mount without ever leaking a
// prior instance (Chart.js does not garbage-collect an old chart on its
// own if you just construct a new one over the same canvas -- explicit
// destroy() is required, this is the one place that happens).
const _chartJsInstances = new WeakMap();

/**
 * Thin wrapper around `new Chart(canvasEl, config)` -- destroys whatever
 * was previously mounted on this canvas first. `config` is a full Chart.js
 * config object; callers build it via buildChartJsConfig() below rather
 * than constructing one by hand every time.
 */
function renderChart(canvasEl, config) {
	const existing = _chartJsInstances.get(canvasEl);
	if (existing) existing.destroy();
	const chart = new Chart(canvasEl, config);
	_chartJsInstances.set(canvasEl, chart);
	return chart;
}

/**
 * Builds a Chart.js config for one of this app's 6 supported chart kinds,
 * from the same `entries` shape renderBarChart already uses:
 *   single-series: [{label, value}, ...]
 *   multi-series (stacked-bar/area-stacked only): [{label, values: [...]}, ...] + seriesLabels
 *
 * `kind`: "bar" | "stacked-bar" | "line" | "area" | "donut" | "pie".
 * `valueFormatter`: controls tooltip value text (e.g. fmtBytes).
 * `horizontal`: bar-only, ranked horizontal bars (Top Clients style).
 */
function buildChartJsConfig(kind, entries, { seriesLabels = null, valueFormatter = (v) => String(v), horizontal = false } = {}) {
	const labels = entries.map(e => e.label);
	const gridColor = cssVar("--border-light");
	const tickColor = cssVar("--text-muted");
	const tooltipBg = cssVar("--surface-alt");
	const tooltipBorder = cssVar("--border-light");
	const tooltipText = cssVar("--text");

	// Category-axis ticks (dates/day-names/bucket labels) are left as their
	// own string values -- only the VALUE axis (Y for a normal vertical
	// chart, X for a horizontal bar) runs through valueFormatter, so a
	// byte/duration/count-valued chart shows "4.8MB"/"1h 2m" on its axis
	// the same way its tooltip already does, instead of Chart.js's default
	// raw-number tick formatting. Was previously wired into the tooltip
	// callback only (see commonPlugins.tooltip below) -- ticks had no
	// callback at all, which is exactly why every byte-valued chart's axis
	// showed e.g. "52428800" instead of "50MB" before this fix.
	const categoryTicks = { color: tickColor };
	const valueTicks = { color: tickColor, callback: (v) => valueFormatter(v) };
	const commonScales = {
		x: { grid: { color: gridColor }, ticks: categoryTicks },
		y: { grid: { color: gridColor }, ticks: valueTicks, beginAtZero: true },
	};
	// Horizontal bars (indexAxis: "y") swap which axis holds values -- X
	// becomes the value axis, Y becomes the category axis -- so the tick
	// callback has to move with it, not just reuse commonScales verbatim.
	const horizontalScales = {
		x: { grid: { color: gridColor }, ticks: valueTicks, beginAtZero: true },
		y: { grid: { color: gridColor }, ticks: categoryTicks },
	};
	const commonPlugins = {
		legend: { display: !!seriesLabels, labels: { color: tickColor } },
		tooltip: {
			backgroundColor: tooltipBg, borderColor: tooltipBorder, borderWidth: 1, titleColor: tooltipText, bodyColor: tooltipText,
			callbacks: { label: (ctx) => `${ctx.dataset.label ? ctx.dataset.label + ": " : ""}${valueFormatter(ctx.parsed.y ?? ctx.parsed ?? ctx.raw)}` },
		},
	};

	if (kind === "donut" || kind === "pie") {
		return {
			type: kind === "donut" ? "doughnut" : "pie",
			data: {
				labels,
				datasets: [{
					data: entries.map(e => e.value),
					backgroundColor: entries.map((_, i) => CHART_JS_PALETTE.fill(i, 0.85)),
					borderColor: entries.map((_, i) => CHART_JS_PALETTE.line(i)),
					borderWidth: 1,
				}],
			},
			options: {
				responsive: true, maintainAspectRatio: false,
				plugins: {
					legend: { display: true, position: "right", labels: { color: tickColor } },
					tooltip: {
						backgroundColor: tooltipBg, borderColor: tooltipBorder, borderWidth: 1, titleColor: tooltipText, bodyColor: tooltipText,
						// A donut/pie's whole point is share-of-whole, but the label
						// callback only ever showed the raw formatted value with no
						// sense of how big a slice it actually is -- added the
						// percentage-of-total alongside it (e.g. country-distribution
						// donuts on Reports/My Reports), computed from this dataset's
						// own values rather than assuming entries/valueFormatter
						// already carry a percentage anywhere.
						callbacks: {
							label: (ctx) => {
								const total = ctx.dataset.data.reduce((sum, v) => sum + (v || 0), 0);
								const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : "0.0";
								return `${ctx.label}: ${valueFormatter(ctx.parsed)} (${pct}%)`;
							},
						},
					},
				},
			},
		};
	}

	if (kind === "bar" && horizontal) {
		return {
			type: "bar",
			data: {
				labels,
				datasets: [{
					data: entries.map(e => e.value),
					backgroundColor: entries.map((_, i) => CHART_JS_PALETTE.fill(i, 0.85)),
					borderColor: entries.map((_, i) => CHART_JS_PALETTE.line(i)),
					borderWidth: 1,
				}],
			},
			options: {
				indexAxis: "y", responsive: true, maintainAspectRatio: false,
				scales: horizontalScales,
				plugins: {
					...commonPlugins,
					legend: { display: false },
					// commonPlugins.tooltip's callback reads ctx.parsed.y, which is
					// correct for a normal vertical chart but WRONG here: indexAxis:
					// "y" swaps which parsed field holds the value (Chart.js puts it
					// in .x for a horizontal bar, .y becomes the category index) --
					// found while auditing every chart's tooltip content, this was
					// showing a raw category index (0, 1, 2...) instead of the
					// formatted byte value on e.g. Reports' "Top Clients by Data
					// Usage" chart.
					tooltip: {
						...commonPlugins.tooltip,
						callbacks: { label: (ctx) => `${ctx.label}: ${valueFormatter(ctx.parsed.x)}` },
					},
				},
			},
		};
	}

	const isArea = kind === "area";
	const isStacked = kind === "stacked-bar";
	const isLineFamily = kind === "line" || isArea;
	const datasets = seriesLabels
		? seriesLabels.map((label, i) => ({
			label,
			data: entries.map(e => e.values[i]),
			backgroundColor: isLineFamily ? CHART_JS_PALETTE.fill(i, isArea ? 0.35 : 0.85) : CHART_JS_PALETTE.fill(i, 0.85),
			borderColor: CHART_JS_PALETTE.line(i),
			borderWidth: isLineFamily ? 2 : 1,
			fill: isArea,
			tension: isLineFamily ? 0.3 : 0,
			pointRadius: isLineFamily ? 2 : 0,
		}))
		: [{
			label: null,
			data: entries.map(e => e.value),
			backgroundColor: isLineFamily ? CHART_JS_PALETTE.fill(0, isArea ? 0.35 : 0.85) : CHART_JS_PALETTE.fill(0, 0.85),
			borderColor: CHART_JS_PALETTE.line(0),
			borderWidth: isLineFamily ? 2 : 1,
			fill: isArea,
			tension: isLineFamily ? 0.3 : 0,
			pointRadius: isLineFamily ? 2 : 0,
		}];

	return {
		type: isLineFamily ? "line" : "bar",
		data: { labels, datasets },
		options: {
			responsive: true, maintainAspectRatio: false,
			scales: isStacked
				? { x: { ...commonScales.x, stacked: true }, y: { ...commonScales.y, stacked: true } }
				: commonScales,
			plugins: commonPlugins,
		},
	};
}

/**
 * Renders a small chart-type <select> into `mountEl`, calling
 * `onChange(newType)` whenever the user picks a different one. If
 * `storageKey` is given, the choice is persisted to localStorage and
 * restored on the next visit (this is the one client-side UI-preference
 * convention in this app -- narrowly scoped to "which chart type did this
 * card last show", nothing broader). Returns the type that should be used
 * for the very first render (the stored one if valid, else `current`).
 */
function chartTypeSelector(mountEl, { types, current, onChange, storageKey = null }) {
	const CHART_TYPE_LABELS = { bar: "Bar", "stacked-bar": "Stacked Bar", line: "Line", area: "Area", donut: "Donut", pie: "Pie" };
	const stored = storageKey ? localStorage.getItem(storageKey) : null;
	const initial = stored && types.includes(stored) ? stored : current;
	mountEl.innerHTML = `<select class="chart-type-select">${
		types.map(t => `<option value="${t}"${t === initial ? " selected" : ""}>${CHART_TYPE_LABELS[t] || t}</option>`).join("")
	}</select>`;
	mountEl.querySelector("select").addEventListener("change", (e) => {
		if (storageKey) localStorage.setItem(storageKey, e.target.value);
		onChange(e.target.value);
	});
	return initial;
}

/**
 * Bespoke day-of-week x hour-of-day heatmap grid (7 rows x however many
 * columns `colLabels` has, 24 for Peak Usage Hours) -- NOT Chart.js
 * (Chart.js 4's core has no native heatmap chart type without an extra
 * plugin), plain CSS grid + `color-mix()` instead, matching this app's
 * existing zero-extra-dependency posture for anything Chart.js itself
 * doesn't cover. `color-mix(in srgb, var(--surface-alt) X%, var(--accent) Y%)`
 * means the color ramp is derived from whichever of this app's 6 themes is
 * currently active (see style.css's [data-theme="..."] blocks) -- no
 * hardcoded hex, so it's correct under every theme without special-casing
 * any of them, and (unlike the Chart.js charts above) DOES repaint live on
 * a theme switch, since it's a plain CSS custom-property reference, not a
 * baked canvas draw.
 *
 * `matrix`: 2D array, matrix[row][col] = a count/value. `rowLabels`/
 * `colLabels`: display labels for each axis (colLabels may contain empty
 * strings for columns that shouldn't show a tick label, e.g. every 3rd
 * hour only, to avoid 24 crowded labels).
 */
function renderHeatmapGrid(mountEl, matrix, { rowLabels, colLabels, valueFormatter = (v) => String(v) } = {}) {
	const max = Math.max(1, ...matrix.flat());
	if (matrix.length === 0 || matrix.every(row => row.every(v => v === 0))) {
		mountEl.innerHTML = '<p class="muted">Not enough data yet.</p>';
		return;
	}
	const cellsHtml = matrix.map((row, r) => row.map((v, c) => {
		const pct = Math.round((v / max) * 100);
		const bg = v === 0 ? "var(--surface-alt)" : `color-mix(in srgb, var(--surface-alt) ${100 - pct}%, var(--accent) ${pct}%)`;
		// `title` as an ATTRIBUTE here, not a child <title> element -- <title>
		// is only a valid child of <svg>, not a plain <div> (unlike
		// renderDonutChart's SVG circles above, which is a real element there).
		return `<div class="heatmap-cell" style="background:${bg}" title="${escapeHtml(rowLabels[r])}, ${escapeHtml(colLabels[c] || "")}: ${escapeHtml(valueFormatter(v))}"></div>`;
	}).join("")).join("");

	mountEl.innerHTML = `
		<div class="heatmap-grid">
			<div class="heatmap-corner"></div>
			<div class="heatmap-col-labels" style="grid-template-columns:repeat(${colLabels.length}, 1fr)">
				${colLabels.map(l => `<span>${escapeHtml(l)}</span>`).join("")}
			</div>
			<div class="heatmap-row-labels">${rowLabels.map(l => `<span>${escapeHtml(l)}</span>`).join("")}</div>
			<div class="heatmap-cells" style="grid-template-columns:repeat(${colLabels.length}, 1fr)">${cellsHtml}</div>
		</div>`;
}

/**
 * A dependency-free "closed by default, expands into checkable options"
 * multiselect dropdown -- used everywhere this app lets someone pick
 * several teams (add-user, edit-user, profile). A native `<select
 * multiple>` shows every option as an always-open listbox (no real
 * "dropdown" affordance, and it eats vertical space); this instead looks
 * and behaves like a normal closed dropdown until clicked.
 *
 * Usage:
 *   const ms = createMultiselectDropdown(document.getElementById("mount"));
 *   ms.setOptions([{id: 1, label: "Infra"}, {id: 2, label: "Security"}]);
 *   ms.setSelected([1]);
 *   ms.getSelected(); // -> [1]
 *
 * `idType` ("number", the default, or "string") controls how option ids
 * round-trip through setSelected/getSelected -- team ids are numeric
 * (matching the API), but this same widget is also used for country-code
 * multiselects (allowed-login-countries), where ids are ISO alpha-2
 * strings like "PK" and `Number("PK")` would silently become NaN.
 * `emptyLabel`/`unitLabel` customize the panel's zero-options message and
 * the toggle's "N selected" text (default "teams", overridden by callers
 * picking something else, e.g. "countries").
 */
function createMultiselectDropdown(root, {
	placeholder = "Select…", disabled = false, idType = "number",
	emptyLabel = "No teams yet.", unitLabel = "teams",
	// searchable mode (users.html's City/ASN pickers): instead of a single
	// setOptions() call with the full list up front, the panel shows a
	// search box and calls onSearch(query) -- async, returns
	// { results: [{id,label}], total } -- on open and on every keystroke
	// (debounced). Exists because some of those lists run into the tens
	// of thousands of entries (e.g. ~18.6k ASNs just for the US, ~78k for
	// "any country") -- shipping all of that to the browser and rendering
	// it as that many checkboxes on every page load was a real, measured
	// performance regression (Users page went from instant to
	// multi-second). searchable:false (the default) preserves the exact
	// prior behavior for every other caller (teams, the country picker).
	searchable = false, onSearch = null, searchPlaceholder = "Type to search…",
	// localFilter mode: like searchable, shows a search box in the panel,
	// but filters the already-loaded `options` array in-browser on every
	// keystroke instead of round-tripping to onSearch -- for lists small
	// enough to ship whole (e.g. the ~196-entry country list) where a
	// server round trip would be overkill, but scrolling an unfiltered
	// flat list to find one entry is still real friction. Mutually
	// exclusive with `searchable` (localFilter is ignored if searchable
	// is also set -- searchable's server-driven mode wins).
	localFilter = false,
	// single mode: selecting an option clears any other selection and
	// auto-closes the panel (combobox-style), for fields backed by a
	// single-value model (e.g. a VPN client's one restricted country)
	// rather than a genuine multi-select. getSelected()/setSelected() keep
	// their existing array-shaped API (0 or 1 id) either way -- callers
	// don't need to special-case anything beyond passing single:true.
	single = false,
} = {}) {
	const hasSearchBox = searchable || localFilter;
	root.classList.add("ms-dropdown");
	root.innerHTML = `
		<button type="button" class="ms-toggle"${disabled ? " disabled" : ""}>
			<span class="ms-toggle-label">${escapeHtml(placeholder)}</span>
			<span class="ms-toggle-caret">▾</span>
		</button>
		<div class="ms-panel">
			${hasSearchBox ? `<input type="text" class="ms-search" placeholder="${escapeHtml(searchPlaceholder)}">` : ""}
			<div class="ms-options"></div>
			${searchable ? `<div class="ms-hint muted"></div>` : ""}
		</div>`;
	if (disabled) root.classList.add("ms-disabled");

	const toggle = root.querySelector(".ms-toggle");
	const toggleLabel = root.querySelector(".ms-toggle-label");
	const panel = root.querySelector(".ms-panel");
	const optionsEl = root.querySelector(".ms-options");
	const searchEl = hasSearchBox ? root.querySelector(".ms-search") : null;
	const hintEl = searchable ? root.querySelector(".ms-hint") : null;
	const castId = idType === "string" ? String : Number;
	let options = [];
	// Only populated/used in localFilter mode -- the unfiltered full list,
	// so a keystroke can narrow `options` down and a cleared search box
	// can restore the whole thing without re-fetching anything.
	let fullOptions = [];
	let selected = new Set();
	let searchTimer = null;
	// Accumulates label-by-id across every setOptions()/search result
	// batch, not just the currently-shown one -- needed for callers that
	// swap the option list in and out (e.g. users.html's country ->
	// city/ASN cascading pickers): a selection made while "Pakistan" was
	// loaded should still show its real name in the toggle button/count
	// after switching to "United States", even though that id is no
	// longer in `options`.
	const labelCache = new Map();

	function refreshLabel() {
		if (selected.size === 0) {
			toggleLabel.textContent = placeholder;
			toggleLabel.classList.add("muted");
		} else {
			const names = [...selected].map(id => labelCache.get(id) ?? String(id));
			toggleLabel.textContent = names.length <= 2 ? names.join(", ") : `${names.length} ${unitLabel} selected`;
			toggleLabel.classList.remove("muted");
		}
	}

	function renderOptions() {
		optionsEl.innerHTML = options.length === 0
			? `<div class="ms-empty muted">${escapeHtml(emptyLabel)}</div>`
			: options.map(o => `
				<label class="ms-option">
					<input type="checkbox" value="${escapeHtml(String(o.id))}" ${selected.has(o.id) ? "checked" : ""}>
					<span>${escapeHtml(o.label)}</span>
				</label>`).join("");
		optionsEl.querySelectorAll('input[type="checkbox"]').forEach(cb => {
			cb.addEventListener("change", () => {
				const id = castId(cb.value);
				if (cb.checked) {
					if (single) {
						// Clear any other selection first -- combobox
						// semantics, not a real multiselect. Re-render so
						// every other checkbox reflects the now-cleared
						// state, then close the panel (picking a value is
						// the terminal action in single mode; there's
						// nothing else to do once you've chosen one).
						selected.clear();
						selected.add(id);
						renderOptions();
						panel.classList.remove("open");
					} else {
						selected.add(id);
					}
				} else {
					selected.delete(id);
				}
				refreshLabel();
			});
		});
	}

	async function runSearch(query) {
		if (!onSearch) return;
		optionsEl.innerHTML = `<div class="ms-empty muted">Searching…</div>`;
		if (hintEl) hintEl.textContent = "";
		let result;
		try {
			result = await onSearch(query);
		} catch (e) {
			optionsEl.innerHTML = `<div class="ms-empty muted">Couldn't load -- try again.</div>`;
			return;
		}
		const results = result?.results ?? [];
		const total = result?.total ?? results.length;
		results.forEach(o => labelCache.set(o.id, o.label));
		options = results;
		renderOptions();
		refreshLabel();
		if (hintEl) {
			hintEl.textContent = results.length === 0 ? ""
				: total > results.length ? `Showing ${results.length} of ${total.toLocaleString()} -- type to narrow`
				: `${results.length} shown`;
		}
	}

	if (searchable) {
		searchEl.addEventListener("input", () => {
			clearTimeout(searchTimer);
			searchTimer = setTimeout(() => runSearch(searchEl.value.trim()), 250);
		});
	} else if (localFilter) {
		// No debounce/round-trip needed -- this is a plain in-memory
		// Array.filter over whatever setOptions() already loaded, cheap
		// enough to run on every keystroke directly.
		searchEl.addEventListener("input", () => {
			const q = searchEl.value.trim().toLowerCase();
			options = q ? fullOptions.filter(o => o.label.toLowerCase().includes(q)) : fullOptions;
			renderOptions();
		});
	}

	toggle.addEventListener("click", () => {
		if (disabled) return;
		const willOpen = !panel.classList.contains("open");
		document.querySelectorAll(".ms-panel.open").forEach(p => p.classList.remove("open"));
		if (willOpen) {
			panel.classList.add("open");
			// Lazy-load: a searchable picker fetches nothing until the
			// admin actually opens it, not on page load -- see the
			// searchable option's docstring above for why that matters.
			if (searchable) runSearch(searchEl.value.trim());
		}
	});
	document.addEventListener("click", (ev) => {
		if (!root.contains(ev.target)) panel.classList.remove("open");
	});

	return {
		setOptions(opts) {
			// Non-searchable / localFilter mode only -- searchable pickers
			// manage their own `options` internally via runSearch().
			options = opts;
			if (localFilter) fullOptions = opts;  // keep the unfiltered copy around
			opts.forEach(o => labelCache.set(o.id, o.label));
			renderOptions();
			refreshLabel();
		},
		setSelected(ids) {
			selected = new Set((ids || []).map(castId));
			renderOptions();
			refreshLabel();
		},
		getSelected() {
			return [...selected];
		},
		reset() {
			selected = new Set();
			// Only searchable pickers clear `options` here -- they refetch
			// on next open via runSearch(), so an empty list is transient.
			// Non-searchable pickers (teams, the country restriction list)
			// get their options via a single setOptions() call at page
			// load and never repopulate them on their own -- wiping
			// `options` here left them permanently empty (showing
			// emptyLabel forever) after any reset()/form-clear, until a
			// full page reload re-ran that initial setOptions() call.
			// localFilter pickers are the same "single setOptions() call at
			// page load" shape as non-searchable ones -- just restore the
			// unfiltered full list rather than wiping it.
			if (searchable) options = [];
			if (localFilter) options = fullOptions;
			if (searchEl) searchEl.value = "";
			if (hintEl) hintEl.textContent = "";
			renderOptions();
			refreshLabel();
		},
		refresh() {
			// Re-runs the current search -- for searchable pickers whose
			// results depend on external state that just changed (e.g.
			// users.html's country <select> next to the picker).
			if (searchable) runSearch(searchEl.value.trim());
		},
		selectedLabels() {
			// Every currently-selected id's label, even ones from an
			// option batch that's no longer loaded (see labelCache above)
			// -- used by users.html to render a "currently selected"
			// summary next to the country-scoped picker.
			return [...selected].map(id => ({ id, label: labelCache.get(id) ?? String(id) }));
		},
	};
}

/**
 * Copies `text` to the clipboard, robust to running over plain HTTP: the
 * modern `navigator.clipboard` API is only available in a secure context
 * (HTTPS or localhost) -- this app doesn't have TLS termination yet (see
 * README's "Planned (phase 2)"), so that API is silently `undefined` in
 * production today, not just occasionally failing. Falls through to the
 * legacy `document.execCommand('copy')` approach (deprecated but still
 * functional over plain HTTP in most browsers), and if even that fails,
 * selects `sourceEl`'s text (when it's a text field) so manual Ctrl+C is a
 * single keystroke instead of "go find and select it yourself."
 *
 * Returns true if the text actually made it onto the clipboard
 * automatically, false if it only got as far as being selected for a
 * manual copy.
 */
async function copyTextToClipboard(text, sourceEl) {
	if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
		try {
			await navigator.clipboard.writeText(text);
			return true;
		} catch (_) { /* fall through to the legacy path below */ }
	}

	const usingSourceEl = sourceEl && typeof sourceEl.select === "function";
	const ta = usingSourceEl ? sourceEl : document.createElement("textarea");
	if (!usingSourceEl) {
		ta.value = text;
		ta.setAttribute("readonly", "");
		ta.style.position = "fixed";
		ta.style.opacity = "0";
		ta.style.pointerEvents = "none";
		document.body.appendChild(ta);
	}
	ta.focus();
	ta.select();
	if (typeof ta.setSelectionRange === "function") ta.setSelectionRange(0, ta.value.length);

	let copied = false;
	try {
		copied = document.execCommand("copy");
	} catch (_) {
		copied = false;
	}
	if (!usingSourceEl) ta.remove();
	// On the failure path, if we were given a real on-page textarea, leave
	// its text selected (re-select in case removing a temporary element
	// above stole focus) so the fallback advice is actionable.
	if (!copied && usingSourceEl) {
		ta.focus();
		ta.select();
	}
	return copied;
}

/**
 * Triggers a browser "Save As" download of `text` as a plain-text file
 * named `filename` -- a Blob + object-URL + synthetic <a download> click,
 * the standard client-only way to hand the user a file with no server
 * round-trip. Used for MFA recovery codes (mfa_setup.html, profile.html)
 * so "save these somewhere safe" has a one-click option beyond manual
 * copy/paste. Revokes the object URL right after the click so it doesn't
 * linger in memory.
 */
function downloadTextFile(filename, text) {
	const blob = new Blob([text], { type: "text/plain" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.style.display = "none";
	document.body.appendChild(a);
	a.click();
	a.remove();
	URL.revokeObjectURL(url);
}

/**
 * Renders a Copy/Download button pair into `mountEl` for a set of MFA
 * recovery `codes` -- shared by mfa_setup.html (first-time enrollment) and
 * profile.html (regenerate) so both places offer the same "save these now,
 * they won't be shown again" affordances instead of leaving the operator
 * to manually select/retype a plaintext block (or, worse, screenshot a
 * plain `alert()`, which is what profile.html's regenerate flow did before
 * this existed).
 */
function renderRecoveryCodesActions(mountEl, codes) {
	mountEl.innerHTML = `
		<button type="button" class="btn-secondary btn-sm" id="rc-copy-btn">Copy Codes</button>
		<button type="button" class="btn-secondary btn-sm" id="rc-download-btn">Download Codes</button>
	`;
	mountEl.querySelector("#rc-copy-btn").addEventListener("click", async (ev) => {
		const ok = await copyTextToClipboard(codes.join("\n"));
		toast(ok ? "Recovery codes copied to clipboard." : "Couldn't copy automatically -- select and copy the codes above manually.", ok ? "success" : "error");
	});
	mountEl.querySelector("#rc-download-btn").addEventListener("click", () => {
		downloadTextFile("recovery-codes.txt",
			"Cyferio VPN Portal -- MFA recovery codes\nEach code works once. Keep this file somewhere safe.\n\n" + codes.join("\n") + "\n");
	});
}

// --- City/ASN cascading "pick a country, search its GeoIP-real values"
// pickers -- shared by users.html's Login Restrictions panels AND
// clients.html's Manage Restrictions dialog (both need identical City/ASN
// pickers now that Location & Network Restrictions is a VPN-profile-level
// concept too, not just a User one -- see policy_store.py's module
// docstring). Originally lived only in users.html's own <script> block;
// moved here once a second page needed the exact same widget rather than
// a second, easily-drifting copy. See geo.py for how /api/geo/* is built
// (an offline walk of the actual GeoLite2 databases, so nothing shown
// here can ever be a value GeoIP could never return at connect/login
// time).
//
// Lazy end to end -- NOTHING here fetches until the admin actually opens
// this picker's dropdown, and the multiselect itself is in searchable
// mode (capped, server-ranked results per keystroke) rather than ever
// holding a whole country's list client-side. Both matter: some countries
// have thousands of cities/ASNs (the US alone: ~11.7k cities, ~18.6k
// ASNs) and "any country" ASN search spans ~78k entries.
//
// wireGeoPicker returns { onSearch } for the multiselect's searchable mode
// -- doesn't touch the multiselect widget directly, since it doesn't exist
// yet at the point this needs to be called (see createGeoPicker below: the
// country <select>'s wiring and the multiselect's own onSearch both need
// this same closure, but the multiselect needs onSearch to already exist
// before it can be constructed).
function wireGeoPicker({ countrySelectEl, kind, buildingEl }) {
	// kind: "cities" or "asns". ASN's country select additionally carries
	// a "" (any country) option already in the HTML -- searches every
	// known network when no specific country is picked.
	const countriesUrl = kind === "cities" ? "/api/geo/countries-with-cities" : "/api/geo/countries-with-asns";
	const toOption = kind === "cities"
		? (v) => ({ id: v, label: v })
		: (v) => ({ id: v.asn, label: `${v.asn} — ${v.org}` });
	let countriesLoaded = false;

	async function loadCountriesOnce() {
		if (countriesLoaded) return;
		countriesLoaded = true;
		try {
			const [status, countries] = await Promise.all([
				apiFetch("/api/geo/status"),
				apiFetch(countriesUrl),
			]);
			const ready = kind === "cities" ? status.city_ready : status.asn_ready;
			if (buildingEl) buildingEl.style.display = ready ? "none" : "";
			const placeholderOpt = kind === "asns"
				? '<option value="">Any country (search all networks)</option>'
				: '<option value="">Select a country…</option>';
			countrySelectEl.innerHTML = placeholderOpt + countries
				.map(code => `<option value="${code}">${escapeHtml(_COUNTRY_NAME_BY_CODE[code] || code)} (${code})</option>`)
				.join("");
		} catch (e) {
			countriesLoaded = false; // allow a retry next time the picker opens
			toast(e.message, "error");
		}
	}

	// Opening the country <select> itself is also a natural "the admin is
	// about to use this picker" signal, so the country list loads then
	// too, not just on the multiselect's own open -- whichever happens
	// first.
	countrySelectEl.addEventListener("mousedown", loadCountriesOnce, { once: true });

	return async function onSearch(q) {
		await loadCountriesOnce();
		const country = countrySelectEl.value;
		if (kind === "cities" && !country) {
			return { results: [], total: 0 }; // no "any country" mode for cities -- see module comment above
		}
		const params = new URLSearchParams();
		if (country) params.set("country", country);
		if (q) params.set("q", q);
		const { results, total } = await apiFetch(`/api/geo/${kind}?${params.toString()}`);
		return { results: results.map(toOption), total };
	};
}

function createGeoPicker({ mountEl, countrySelectEl, kind, buildingEl, pickerOpts }) {
	const onSearch = wireGeoPicker({ countrySelectEl, kind, buildingEl });
	const ms = createMultiselectDropdown(mountEl, { ...pickerOpts, searchable: true, onSearch });
	// Re-searches with whatever's currently typed whenever the country
	// changes -- this is the one piece that genuinely needs the real `ms`
	// instance, so it's wired here, after ms exists, rather than inside
	// wireGeoPicker.
	countrySelectEl.addEventListener("change", () => ms.refresh());
	return ms;
}

// Default { placeholder, unitLabel, emptyLabel, searchPlaceholder } sets
// for createGeoPicker's `pickerOpts` -- shared verbatim between
// users.html's two Login Restrictions panels (Add/Edit) and clients.html's
// Manage Restrictions dialog, `idType: "string"` in both since city names
// and "AS12345" values are never numeric ids.
const CITY_PICKER_OPTS = { placeholder: "No cities selected", idType: "string", unitLabel: "cities", emptyLabel: "No matching cities -- pick a country above, or try a different search.", searchPlaceholder: "Pick a country, then search its cities…" };
const ASN_PICKER_OPTS = { placeholder: "No networks selected", idType: "string", unitLabel: "networks", emptyLabel: "No matching networks -- try a different search.", searchPlaceholder: "Search by network/org name or AS number…" };

// Splits a "one entry per line" restriction textarea (allowed IPs) into a
// clean array -- blank lines and stray commas both tolerated. Shared by
// users.html's and clients.html's restriction forms; server-side
// validators (geo_validators.py's valid_ip_list) are the real check, this
// just turns free text into an array before it's sent.
function parseLineList(text) {
	return text.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
}

// Static ISO 3166-1 alpha-2 country list (code, English short name) --
// used by the VPN Clients page's "Manage Restrictions" dialog to populate
// a per-client country-restriction <select>. Self-contained, no runtime
// API call, same principle as the rest of this app's static assets.
// There is deliberately no "current deployment's country" concept here --
// every client picks independently from the full list (or "Unrestricted").
const ISO_3166_COUNTRIES = [
	["AF", "Afghanistan"], ["AL", "Albania"], ["DZ", "Algeria"], ["AS", "American Samoa"], ["AD", "Andorra"],
	["AO", "Angola"], ["AI", "Anguilla"], ["AQ", "Antarctica"], ["AG", "Antigua and Barbuda"], ["AR", "Argentina"],
	["AM", "Armenia"], ["AW", "Aruba"], ["AU", "Australia"], ["AT", "Austria"], ["AZ", "Azerbaijan"],
	["BS", "Bahamas"], ["BH", "Bahrain"], ["BD", "Bangladesh"], ["BB", "Barbados"], ["BY", "Belarus"],
	["BE", "Belgium"], ["BZ", "Belize"], ["BJ", "Benin"], ["BM", "Bermuda"], ["BT", "Bhutan"],
	["BO", "Bolivia"], ["BA", "Bosnia and Herzegovina"], ["BW", "Botswana"], ["BR", "Brazil"], ["BN", "Brunei"],
	["BG", "Bulgaria"], ["BF", "Burkina Faso"], ["BI", "Burundi"], ["CV", "Cabo Verde"], ["KH", "Cambodia"],
	["CM", "Cameroon"], ["CA", "Canada"], ["KY", "Cayman Islands"], ["CF", "Central African Republic"], ["TD", "Chad"],
	["CL", "Chile"], ["CN", "China"], ["CO", "Colombia"], ["KM", "Comoros"], ["CG", "Congo"],
	["CD", "Congo (DRC)"], ["CR", "Costa Rica"], ["CI", "Côte d'Ivoire"], ["HR", "Croatia"], ["CU", "Cuba"],
	["CW", "Curaçao"], ["CY", "Cyprus"], ["CZ", "Czechia"], ["DK", "Denmark"], ["DJ", "Djibouti"],
	["DM", "Dominica"], ["DO", "Dominican Republic"], ["EC", "Ecuador"], ["EG", "Egypt"], ["SV", "El Salvador"],
	["GQ", "Equatorial Guinea"], ["ER", "Eritrea"], ["EE", "Estonia"], ["SZ", "Eswatini"], ["ET", "Ethiopia"],
	["FJ", "Fiji"], ["FI", "Finland"], ["FR", "France"], ["GF", "French Guiana"], ["PF", "French Polynesia"],
	["GA", "Gabon"], ["GM", "Gambia"], ["GE", "Georgia"], ["DE", "Germany"], ["GH", "Ghana"],
	["GI", "Gibraltar"], ["GR", "Greece"], ["GL", "Greenland"], ["GD", "Grenada"], ["GP", "Guadeloupe"],
	["GU", "Guam"], ["GT", "Guatemala"], ["GG", "Guernsey"], ["GN", "Guinea"], ["GW", "Guinea-Bissau"],
	["GY", "Guyana"], ["HT", "Haiti"], ["HN", "Honduras"], ["HK", "Hong Kong"], ["HU", "Hungary"],
	["IS", "Iceland"], ["IN", "India"], ["ID", "Indonesia"], ["IR", "Iran"], ["IQ", "Iraq"],
	["IE", "Ireland"], ["IM", "Isle of Man"], ["IL", "Israel"], ["IT", "Italy"], ["JM", "Jamaica"],
	["JP", "Japan"], ["JE", "Jersey"], ["JO", "Jordan"], ["KZ", "Kazakhstan"], ["KE", "Kenya"],
	["KI", "Kiribati"], ["KP", "Korea (North)"], ["KR", "Korea (South)"], ["KW", "Kuwait"], ["KG", "Kyrgyzstan"],
	["LA", "Laos"], ["LV", "Latvia"], ["LB", "Lebanon"], ["LS", "Lesotho"], ["LR", "Liberia"],
	["LY", "Libya"], ["LI", "Liechtenstein"], ["LT", "Lithuania"], ["LU", "Luxembourg"], ["MO", "Macao"],
	["MG", "Madagascar"], ["MW", "Malawi"], ["MY", "Malaysia"], ["MV", "Maldives"], ["ML", "Mali"],
	["MT", "Malta"], ["MH", "Marshall Islands"], ["MQ", "Martinique"], ["MR", "Mauritania"], ["MU", "Mauritius"],
	["MX", "Mexico"], ["FM", "Micronesia"], ["MD", "Moldova"], ["MC", "Monaco"], ["MN", "Mongolia"],
	["ME", "Montenegro"], ["MS", "Montserrat"], ["MA", "Morocco"], ["MZ", "Mozambique"], ["MM", "Myanmar"],
	["NA", "Namibia"], ["NR", "Nauru"], ["NP", "Nepal"], ["NL", "Netherlands"], ["NC", "New Caledonia"],
	["NZ", "New Zealand"], ["NI", "Nicaragua"], ["NE", "Niger"], ["NG", "Nigeria"], ["NU", "Niue"],
	["MK", "North Macedonia"], ["NO", "Norway"], ["OM", "Oman"], ["PK", "Pakistan"], ["PW", "Palau"],
	["PS", "Palestine"], ["PA", "Panama"], ["PG", "Papua New Guinea"], ["PY", "Paraguay"], ["PE", "Peru"],
	["PH", "Philippines"], ["PL", "Poland"], ["PT", "Portugal"], ["PR", "Puerto Rico"], ["QA", "Qatar"],
	["RO", "Romania"], ["RU", "Russia"], ["RW", "Rwanda"], ["KN", "Saint Kitts and Nevis"], ["LC", "Saint Lucia"],
	["VC", "Saint Vincent and the Grenadines"], ["WS", "Samoa"], ["SM", "San Marino"], ["ST", "Sao Tome and Principe"], ["SA", "Saudi Arabia"],
	["SN", "Senegal"], ["RS", "Serbia"], ["SC", "Seychelles"], ["SL", "Sierra Leone"], ["SG", "Singapore"],
	["SK", "Slovakia"], ["SI", "Slovenia"], ["SB", "Solomon Islands"], ["SO", "Somalia"], ["ZA", "South Africa"],
	["SS", "South Sudan"], ["ES", "Spain"], ["LK", "Sri Lanka"], ["SD", "Sudan"], ["SR", "Suriname"],
	["SE", "Sweden"], ["CH", "Switzerland"], ["SY", "Syria"], ["TW", "Taiwan"], ["TJ", "Tajikistan"],
	["TZ", "Tanzania"], ["TH", "Thailand"], ["TL", "Timor-Leste"], ["TG", "Togo"], ["TO", "Tonga"],
	["TT", "Trinidad and Tobago"], ["TN", "Tunisia"], ["TR", "Turkey"], ["TM", "Turkmenistan"], ["TV", "Tuvalu"],
	["UG", "Uganda"], ["UA", "Ukraine"], ["AE", "United Arab Emirates"], ["GB", "United Kingdom"], ["US", "United States"],
	["UY", "Uruguay"], ["UZ", "Uzbekistan"], ["VU", "Vanuatu"], ["VA", "Vatican City"], ["VE", "Venezuela"],
	["VN", "Vietnam"], ["VG", "Virgin Islands (British)"], ["VI", "Virgin Islands (U.S.)"], ["YE", "Yemen"], ["ZM", "Zambia"],
	["ZW", "Zimbabwe"],
];

function populateCountrySelect(selectEl, selectedCode) {
	selectEl.innerHTML = '<option value="">Unrestricted (any country)</option>' +
		ISO_3166_COUNTRIES.map(([code, name]) => `<option value="${code}">${escapeHtml(name)} (${code})</option>`).join("");
	selectEl.value = selectedCode || "";
}

// name lookup for a country code from the same ISO_3166_COUNTRIES list above
// -- used anywhere a restriction needs to be shown back to an admin as text
// (table badges, live restriction summaries) rather than picked from a
// <select>. Falls back to the raw code itself if somehow not found, so a
// stale/foreign code already saved in client_policy.json never disappears
// from the UI silently.
const _COUNTRY_NAME_BY_CODE = Object.fromEntries(ISO_3166_COUNTRIES);
function countryName(code) {
	return _COUNTRY_NAME_BY_CODE[code] || code;
}

// Static country -> international calling ("dial") code table -- a
// different dataset from ISO_3166_COUNTRIES above (that one has no dial
// codes, and is used for GeoIP country restriction, an unrelated feature).
// Country names are deliberately kept the same as ISO_3166_COUNTRIES's for
// consistency across the app, even though this is a separate list. Covers
// every country in ISO_3166_COUNTRIES (~195 entries) so nothing that shows
// up in the GeoIP restriction dropdown is missing here.
//
// NANP members (US/CA + the Caribbean island nations that share the "+1"
// country code) are listed with their real, distinguishing area code
// (e.g. Jamaica "+1876") rather than a bare "+1" for every one of them --
// that's how every other phone-input widget in the wild disambiguates them,
// and it lets round-tripping a stored number (see _dialCodesByLength below)
// pick the right country back out for e.g. Jamaica instead of always
// falling back to "United States". US and Canada themselves both
// genuinely are just "+1" -- there's no way to tell them apart from the
// number alone, and this app doesn't need to.
const DIAL_CODES = [
	["Afghanistan", "+93"], ["Albania", "+355"], ["Algeria", "+213"], ["American Samoa", "+1684"], ["Andorra", "+376"],
	["Angola", "+244"], ["Anguilla", "+1264"], ["Antigua and Barbuda", "+1268"], ["Argentina", "+54"], ["Armenia", "+374"],
	["Aruba", "+297"], ["Australia", "+61"], ["Austria", "+43"], ["Azerbaijan", "+994"],
	["Bahamas", "+1242"], ["Bahrain", "+973"], ["Bangladesh", "+880"], ["Barbados", "+1246"], ["Belarus", "+375"],
	["Belgium", "+32"], ["Belize", "+501"], ["Benin", "+229"], ["Bermuda", "+1441"], ["Bhutan", "+975"],
	["Bolivia", "+591"], ["Bosnia and Herzegovina", "+387"], ["Botswana", "+267"], ["Brazil", "+55"], ["Brunei", "+673"],
	["Bulgaria", "+359"], ["Burkina Faso", "+226"], ["Burundi", "+257"], ["Cabo Verde", "+238"], ["Cambodia", "+855"],
	["Cameroon", "+237"], ["Canada", "+1"], ["Cayman Islands", "+1345"], ["Central African Republic", "+236"], ["Chad", "+235"],
	["Chile", "+56"], ["China", "+86"], ["Colombia", "+57"], ["Comoros", "+269"], ["Congo", "+242"],
	["Congo (DRC)", "+243"], ["Costa Rica", "+506"], ["Côte d'Ivoire", "+225"], ["Croatia", "+385"], ["Cuba", "+53"],
	["Curaçao", "+599"], ["Cyprus", "+357"], ["Czechia", "+420"], ["Denmark", "+45"], ["Djibouti", "+253"],
	["Dominica", "+1767"], ["Dominican Republic", "+1809"], ["Ecuador", "+593"], ["Egypt", "+20"], ["El Salvador", "+503"],
	["Equatorial Guinea", "+240"], ["Eritrea", "+291"], ["Estonia", "+372"], ["Eswatini", "+268"], ["Ethiopia", "+251"],
	["Fiji", "+679"], ["Finland", "+358"], ["France", "+33"], ["French Guiana", "+594"], ["French Polynesia", "+689"],
	["Gabon", "+241"], ["Gambia", "+220"], ["Georgia", "+995"], ["Germany", "+49"], ["Ghana", "+233"],
	["Gibraltar", "+350"], ["Greece", "+30"], ["Greenland", "+299"], ["Grenada", "+1473"], ["Guadeloupe", "+590"],
	["Guam", "+1671"], ["Guatemala", "+502"], ["Guernsey", "+44"], ["Guinea", "+224"], ["Guinea-Bissau", "+245"],
	["Guyana", "+592"], ["Haiti", "+509"], ["Honduras", "+504"], ["Hong Kong", "+852"], ["Hungary", "+36"],
	["Iceland", "+354"], ["India", "+91"], ["Indonesia", "+62"], ["Iran", "+98"], ["Iraq", "+964"],
	["Ireland", "+353"], ["Isle of Man", "+44"], ["Israel", "+972"], ["Italy", "+39"], ["Jamaica", "+1876"],
	["Japan", "+81"], ["Jersey", "+44"], ["Jordan", "+962"], ["Kazakhstan", "+7"], ["Kenya", "+254"],
	["Kiribati", "+686"], ["Korea (North)", "+850"], ["Korea (South)", "+82"], ["Kuwait", "+965"], ["Kyrgyzstan", "+996"],
	["Laos", "+856"], ["Latvia", "+371"], ["Lebanon", "+961"], ["Lesotho", "+266"], ["Liberia", "+231"],
	["Libya", "+218"], ["Liechtenstein", "+423"], ["Lithuania", "+370"], ["Luxembourg", "+352"], ["Macao", "+853"],
	["Madagascar", "+261"], ["Malawi", "+265"], ["Malaysia", "+60"], ["Maldives", "+960"], ["Mali", "+223"],
	["Malta", "+356"], ["Marshall Islands", "+692"], ["Martinique", "+596"], ["Mauritania", "+222"], ["Mauritius", "+230"],
	["Mexico", "+52"], ["Micronesia", "+691"], ["Moldova", "+373"], ["Monaco", "+377"], ["Mongolia", "+976"],
	["Montenegro", "+382"], ["Montserrat", "+1664"], ["Morocco", "+212"], ["Mozambique", "+258"], ["Myanmar", "+95"],
	["Namibia", "+264"], ["Nauru", "+674"], ["Nepal", "+977"], ["Netherlands", "+31"], ["New Caledonia", "+687"],
	["New Zealand", "+64"], ["Nicaragua", "+505"], ["Niger", "+227"], ["Nigeria", "+234"], ["Niue", "+683"],
	["North Macedonia", "+389"], ["Norway", "+47"], ["Oman", "+968"], ["Pakistan", "+92"], ["Palau", "+680"],
	["Palestine", "+970"], ["Panama", "+507"], ["Papua New Guinea", "+675"], ["Paraguay", "+595"], ["Peru", "+51"],
	["Philippines", "+63"], ["Poland", "+48"], ["Portugal", "+351"], ["Puerto Rico", "+1787"], ["Qatar", "+974"],
	["Romania", "+40"], ["Russia", "+7"], ["Rwanda", "+250"], ["Saint Kitts and Nevis", "+1869"], ["Saint Lucia", "+1758"],
	["Saint Vincent and the Grenadines", "+1784"], ["Samoa", "+685"], ["San Marino", "+378"], ["Sao Tome and Principe", "+239"], ["Saudi Arabia", "+966"],
	["Senegal", "+221"], ["Serbia", "+381"], ["Seychelles", "+248"], ["Sierra Leone", "+232"], ["Singapore", "+65"],
	["Slovakia", "+421"], ["Slovenia", "+386"], ["Solomon Islands", "+677"], ["Somalia", "+252"], ["South Africa", "+27"],
	["South Sudan", "+211"], ["Spain", "+34"], ["Sri Lanka", "+94"], ["Sudan", "+249"], ["Suriname", "+597"],
	["Sweden", "+46"], ["Switzerland", "+41"], ["Syria", "+963"], ["Taiwan", "+886"], ["Tajikistan", "+992"],
	["Tanzania", "+255"], ["Thailand", "+66"], ["Timor-Leste", "+670"], ["Togo", "+228"], ["Tonga", "+676"],
	["Trinidad and Tobago", "+1868"], ["Tunisia", "+216"], ["Turkey", "+90"], ["Turkmenistan", "+993"], ["Tuvalu", "+688"],
	["Uganda", "+256"], ["Ukraine", "+380"], ["United Arab Emirates", "+971"], ["United Kingdom", "+44"], ["United States", "+1"],
	["Uruguay", "+598"], ["Uzbekistan", "+998"], ["Vanuatu", "+678"], ["Vatican City", "+379"], ["Venezuela", "+58"],
	["Vietnam", "+84"], ["Virgin Islands (British)", "+1284"], ["Virgin Islands (U.S.)", "+1340"], ["Yemen", "+967"], ["Zambia", "+260"],
	["Zimbabwe", "+263"],
];

// Longest-dial-code-first copy of DIAL_CODES, used to parse a stored
// "+<dialcode><localnumber>" string back into (dial code, local number) for
// the Edit User dialog: trying the longest codes first is what correctly
// picks e.g. Jamaica's "+1876" out of a number that would otherwise also
// match the shorter generic "+1", since both are valid prefixes of the same
// string.
const _DIAL_CODES_BY_LENGTH = [...DIAL_CODES].sort((a, b) => b[1].length - a[1].length);

/**
 * A reusable phone input: a country dial-code <select> paired with a plain
 * text input for the local number, backed by a single combined value (e.g.
 * "+923001234567") so callers -- and the server, which stores User.phone as
 * one string column -- never need to know it's really two controls.
 *
 * A plain <select> rather than a custom dropdown like
 * createMultiselectDropdown: with 195+ entries a native listbox's built-in
 * type-to-jump keyboard search matters a lot more than visual flourish, and
 * it stays inside this app's existing dark-theme form-control styling for
 * free (see style.css's `select` rules) without reinventing that here.
 *
 * Country name comes before the dial code in both the option's visible
 * text and its sort order (e.g. "Pakistan +92", not "+92 Pakistan") --
 * with a dial code first, every single option's visible text started with
 * "+", so the native <select>'s built-in type-to-jump search (which
 * matches against the FIRST character(s) of the visible text) had nothing
 * to distinguish between; pressing "p" never reliably landed on Pakistan.
 * Name-first fixes that for free, no custom keyboard handling needed.
 *
 * Stored/returned values are dash-grouped ("+92-321-1234567" for Pakistan,
 * "+<dialcode>-<local digits>" everywhere else) -- see routes/users.py's
 * _valid_phone for the server-side format this mirrors exactly and is the
 * real source of truth for.
 *
 * Usage:
 *   const phone = createPhoneInput(document.getElementById("mount"));
 *   phone.setValue(u.phone);       // parses "+92-321-1234567" -> ("+92", "3331234567")
 *   phone.getValue();              // -> "+92-321-1234567", or "" if local number is blank
 *   phone.getLocalInputEl();       // the local-number <input>, for attaching blur/input validation
 */
const _DIAL_CODES_BY_NAME = [...DIAL_CODES].sort((a, b) => a[0].localeCompare(b[0]));

// Preselected on a brand-new (empty) phone input -- avoids everyone who
// creates a user having to hunt for the same country every time on this
// deployment. Not a hardcoded assumption anywhere else in the app (GeoIP
// client restrictions, etc. all stay per-client/admin-chosen) -- purely a
// default a self-hoster can change to their own country's dial code here.
const DEFAULT_DIAL_CODE = "+92"; // Pakistan

// Pakistan's mobile numbers are always a 3-digit prefix + 7-digit
// subscriber number (+92-321-1234567) -- this is the one dial code this
// widget actively reformats as-you-type (auto-inserting the dash after 3
// digits) and shows a concrete example placeholder for, matching the
// backend's own _PHONE_PK_RE strict check. Every other country keeps a
// generic placeholder and a single dial-code/local-number dash, with no
// further internal grouping assumed (see routes/users.py's
// _PHONE_GENERAL_RE for why: there's no one grouping that fits 200+
// countries' numbering plans).
function _formatLocalDigits(dial, digits) {
	if (dial === "+92" && digits.length > 3) {
		return `${digits.slice(0, 3)}-${digits.slice(3, 10)}`;
	}
	return digits;
}

function createPhoneInput(root) {
	root.classList.add("phone-input");
	root.innerHTML = `
		<select class="phone-dial-select" aria-label="Country code">
			${_DIAL_CODES_BY_NAME.map(([name, dial]) => `<option value="${dial}"${dial === DEFAULT_DIAL_CODE ? " selected" : ""}>${escapeHtml(name)} ${dial}</option>`).join("")}
		</select>
		<input type="text" class="phone-local-input" inputmode="tel" placeholder="321-1234567">`;
	const dialSelect = root.querySelector(".phone-dial-select");
	const localInput = root.querySelector(".phone-local-input");

	function refreshPlaceholder() {
		localInput.placeholder = dialSelect.value === "+92" ? "321-1234567" : "Local number";
	}

	// Live-format as the admin types: strip anything non-digit, cap at 10
	// digits (3+7) for Pakistan specifically, re-insert the dash at the
	// right position -- so what's on screen already looks like the
	// required format instead of the admin needing to type dashes
	// themselves or only finding out it's wrong after submitting.
	localInput.addEventListener("input", () => {
		const digits = localInput.value.replace(/\D/g, "").slice(0, dialSelect.value === "+92" ? 10 : 14);
		localInput.value = _formatLocalDigits(dialSelect.value, digits);
	});
	dialSelect.addEventListener("change", () => {
		refreshPlaceholder();
		const digits = localInput.value.replace(/\D/g, "");
		localInput.value = _formatLocalDigits(dialSelect.value, digits);
	});
	refreshPlaceholder();

	return {
		setValue(phone) {
			phone = (phone || "").trim();
			if (!phone) {
				dialSelect.value = DEFAULT_DIAL_CODE;
				localInput.value = "";
				refreshPlaceholder();
				return;
			}
			// Strip dashes before matching against DIAL_CODES (which holds
			// bare "+92" etc.) -- accepts both the new dash-grouped format
			// and any older bare-digit value already sitting in the
			// database from before this format existed.
			const compact = phone.replace(/-/g, "");
			const match = _DIAL_CODES_BY_LENGTH.find(([, dial]) => compact.startsWith(dial));
			if (match) {
				dialSelect.value = match[1];
				localInput.value = _formatLocalDigits(match[1], compact.slice(match[1].length));
			} else {
				// Doesn't cleanly match any known dial code (e.g. a legacy
				// value entered before this UI existed) -- don't crash or
				// guess, just show it raw with the default dial code
				// preselected rather than blank (there's no more "no
				// selection" option now that every <option> has a real
				// dial code -- see the dropdown markup above).
				dialSelect.value = DEFAULT_DIAL_CODE;
				localInput.value = phone;
			}
			refreshPlaceholder();
		},
		getValue() {
			const digits = localInput.value.replace(/\D/g, "");
			if (!digits) return "";
			const dial = dialSelect.value || DEFAULT_DIAL_CODE;
			if (dial === "+92") {
				return digits.length === 10 ? `${dial}-${digits.slice(0, 3)}-${digits.slice(3)}` : `${dial}-${digits}`;
			}
			return `${dial}-${digits}`;
		},
		getLocalInputEl() {
			return localInput;
		},
		reset() {
			dialSelect.value = DEFAULT_DIAL_CODE;
			localInput.value = "";
			refreshPlaceholder();
		},
	};
}

/**
 * Wires up real-time inline validation for a text input: on blur (and on
 * every keystroke once it's already been marked invalid, so the error
 * clears as soon as the user fixes it) runs `validateFn(value) -> error
 * string | null` and toggles an `.input-invalid` border plus a `.field-error`
 * message right below the field. Shared by the email and phone fields on
 * the Add User form, Edit User dialog, and Profile page -- this app had no
 * existing inline-validation convention (checked for `.field-error`/
 * `setCustomValidity` first), so this establishes one rather than blocking
 * submission client-side with nothing but the browser's own default popup.
 * Purely a UX layer: the server-side validator is still the real check --
 * see routes/users.py's _valid_email/_valid_phone.
 */
function attachInlineValidation(inputEl, validateFn) {
	let errorEl = inputEl.nextElementSibling;
	if (!errorEl || !errorEl.classList.contains("field-error")) {
		errorEl = document.createElement("div");
		errorEl.className = "field-error";
		inputEl.insertAdjacentElement("afterend", errorEl);
	}
	function run() {
		const msg = validateFn(inputEl.value);
		inputEl.classList.toggle("input-invalid", !!msg);
		errorEl.textContent = msg || "";
		return !msg;
	}
	inputEl.addEventListener("blur", run);
	inputEl.addEventListener("input", () => {
		if (inputEl.classList.contains("input-invalid")) run();
	});
	return { check: run };
}

/**
 * Backdrop-click-to-close for a native <dialog>. Clicking anywhere inside
 * the dialog's own rendered box (its .dialog-body content, or padding
 * around it) never reaches here since it's inside the element's border
 * box; a click that lands on the <dialog> element itself but outside that
 * box can only be the ::backdrop (the browser routes backdrop clicks to
 * the dialog element, not a separate node) -- checked geometrically via
 * getBoundingClientRect rather than event.target, since the dialog element
 * IS the click target either way. Idempotent to call more than once isn't
 * needed here -- every call site below wires each dialog exactly once, at
 * page load.
 */
function closeOnBackdropClick(dialogEl) {
	dialogEl.addEventListener("click", (ev) => {
		const r = dialogEl.getBoundingClientRect();
		const insideBox = ev.clientX >= r.left && ev.clientX <= r.right && ev.clientY >= r.top && ev.clientY <= r.bottom;
		if (!insideBox) dialogEl.close();
	});
}

/**
 * Latches "dirty" the first time `container`'s contents change after
 * arm() -- used to keep an edit form's Save button disabled until the
 * admin has actually changed something. Relies on bubbling input/change
 * events, which every widget in this app already fires on a real value
 * change: plain inputs/selects/textareas natively, and this app's custom
 * widgets (createMultiselectDropdown's checkbox panel, createPhoneInput's
 * compound field, the geo-picker multiselects) via the real
 * checkboxes/inputs they're built from internally -- deliberately NOT a
 * MutationObserver-based catch-all on top of that, since this app also has
 * pure-presentation DOM mutations inside these same containers that aren't
 * a field change at all (e.g. the collapsible Login Restrictions panel's
 * open/close class toggle) -- a mutation-based latch would misfire dirty
 * on those.
 *
 * arm() takes a snapshot moment: call it right after populating a form for
 * editing (or on page load for an inline, always-editable section like
 * Roles/Teams). disarm() stops tracking -- call on cancel/close and again
 * right after a successful save (so the now-current values don't
 * immediately read as "dirty" against themselves next time the form
 * opens).
 */
function bindDirtyTracking(container, saveBtn) {
	let dirty = false;
	let tracking = false;
	function markDirty() {
		if (!tracking || dirty) return;
		dirty = true;
		saveBtn.disabled = false;
	}
	container.addEventListener("input", markDirty);
	container.addEventListener("change", markDirty);
	function arm() {
		dirty = false;
		tracking = false;
		saveBtn.disabled = true;
		// Populating the form's fields (right before/after this call) is
		// itself a burst of input/change events -- defer arming the latch
		// to the next frame so that populate step doesn't immediately mark
		// the form dirty against itself.
		requestAnimationFrame(() => { tracking = true; });
	}
	function disarm() {
		tracking = false;
	}
	return { arm, disarm, isDirty: () => dirty };
}

/**
 * True if a "restriction kind" (a restrict-toggle + allow-list pair --
 * country/city/ASN/IP, on either Portal Login or VPN Access restrictions)
 * actually changed since `initial` was snapshotted. Used to decide whether
 * to include that kind's fields in a PATCH/PUT body at all -- omitting an
 * UNCHANGED kind, rather than resending its current value, is what lets an
 * admin save an unrelated edit (role, bandwidth, ...) even when that kind's
 * already-stored value happens to contain a city/ASN the GeoIP database no
 * longer recognizes (MaxMind's own data drifts between updates -- a value
 * that validated when it was first saved isn't guaranteed to validate
 * forever). The backend already skips re-validating/re-applying a field
 * that's simply absent from the request (model_fields_set-gated) -- this
 * is what makes that gate actually take effect instead of being defeated
 * by the form always sending every field regardless of whether it was
 * touched. See users.html's openEdit()/edit-form submit handler and
 * clients.html's Manage Restrictions dialog for the two call sites.
 */
function restrictionKindChanged(initial, current) {
	if (initial.restrict !== current.restrict) return true;
	const a = [...initial.list].sort();
	const b = [...current.list].sort();
	if (a.length !== b.length) return true;
	return a.some((v, i) => v !== b[i]);
}

// Character classes kept disjoint and each guaranteed at least one
// occurrence below -- avoids the visually-ambiguous glyphs (l/1/I/O/0)
// that make a freshly-generated password error-prone to retype/read back,
// since it's shown once and never stored in the clear anywhere after.
const _PW_CHAR_CLASSES = [
	"abcdefghjkmnpqrstuvwxyz",
	"ABCDEFGHJKMNPQRSTUVWXYZ",
	"23456789",
	"!@#$%^&*-_=+?",
];
const _PW_ALL_CHARS = _PW_CHAR_CLASSES.join("");

/**
 * Generates a strong random password using the Web Crypto RNG (not
 * Math.random -- that's not cryptographically secure and this value gets
 * handed to real accounts). Rejection-sampled per character so every
 * character class is equally likely regardless of its length (a naive
 * `charset[randomByte % charset.length]` would slightly favor shorter
 * classes' characters), then one character from each of the 4 classes
 * above is guaranteed present by construction, and the whole thing is
 * shuffled (Fisher-Yates, same crypto RNG) so those guaranteed characters
 * aren't predictably clustered at the front.
 */
function generateStrongPassword(length = 16) {
	const bytes = new Uint32Array(1);
	function randomChar(charset) {
		const max = Math.floor(0xFFFFFFFF / charset.length) * charset.length;
		let x;
		do { crypto.getRandomValues(bytes); x = bytes[0]; } while (x >= max);
		return charset[x % charset.length];
	}
	const chars = _PW_CHAR_CLASSES.map(randomChar);
	while (chars.length < length) chars.push(randomChar(_PW_ALL_CHARS));
	for (let i = chars.length - 1; i > 0; i--) {
		const j = Math.floor((crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF) * (i + 1));
		[chars[i], chars[j]] = [chars[j], chars[i]];
	}
	return chars.join("");
}

/**
 * Wires a New Password + Confirm Password pair, plus an optional Generate
 * button, with a shared match-check -- used by both users.html's Add User
 * form (password required) and its Edit User dialog (password optional,
 * "leave blank to keep current"). Generate fills both fields with the same
 * freshly-generated value and flips them to type="text" so the value is
 * actually readable/copyable the one time it's shown (never re-shown, and
 * never sent anywhere except in the form's own submit body).
 */
/**
 * Real-time mirror of routes/users.py's _valid_password complexity rules
 * (min length, 1 uppercase, 1 number, 1 special character) -- server-side
 * is still the real check (and its min-length is admin-configurable via
 * Settings -> Security, which this client-side copy doesn't know about, so
 * it always checks against the fixed default of 8 -- a false-negative
 * here, e.g. an admin who lowered the requirement to 6, just means the
 * server accepts something this warns about unnecessarily, never the
 * reverse). Returns null if `v` satisfies every rule.
 */
/**
 * Real-time mirror of services.openvpn.validator.normalize_mac's tolerance
 * (the same MAC-format check the Python service layer -- and, by
 * extension, openvpn-install.sh's do_add_mac -- actually enforces): 12 hex
 * digits, with colon, dash, dot, or no separator at all, any case. Used by
 * users.html's Add/Edit User MAC field, openvpn_install.html's first-client
 * MAC field, and clients.html's Manage MACs add-MAC field. Server-side
 * (routes/users.py's/routes/clients.py's shared _valid_mac_format) is
 * still the real check; this is just real-time UX feedback so a typo is
 * caught before submit instead of only after a round-trip.
 */
function macError(v) {
	v = (v || "").trim();
	if (!v) return null;
	const hexOnly = v.replace(/[:.\-]/g, "");
	if (!/^[0-9A-Fa-f]{12}$/.test(hexOnly)) {
		return "Enter a valid MAC address, e.g. AA:BB:CC:DD:EE:FF (colons, dashes, or no separator all work).";
	}
	return null;
}

/**
 * Real-time mirror of policy_store.set_policy's/routes/users.py's
 * _valid_bandwidth_gb's bandwidth-quota rule: blank means unlimited (no
 * error), otherwise a number >= 0.1 GB (100 MB). Used by users.html's Add/
 * Edit User bandwidth field and clients.html's Manage Restrictions dialog.
 */
function bandwidthError(v) {
	v = (v || "").trim();
	if (!v) return null; // blank = unlimited, always valid
	const n = Number(v);
	if (!Number.isFinite(n)) return "Bandwidth quota must be a number.";
	if (n < 0.1) return "Bandwidth quota must be at least 0.1 GB (100 MB) -- leave blank for unlimited.";
	return null;
}

/**
 * Generic "is this a whole number within range" check for the numeric
 * Settings fields (SMTP port, session timeout, min password length, audit
 * retention, ...) -- `min`/`max` are inclusive, either can be omitted for
 * an open-ended bound. `emptyOk` lets a blank field mean "use the default"
 * (several of these settings fall back to an env-var default when
 * cleared) rather than being flagged as invalid.
 */
function numberRangeError(v, { min, max, label = "Value", emptyOk = false, allowDecimal = false } = {}) {
	v = (v || "").trim();
	if (!v) return emptyOk ? null : `${label} is required.`;
	if (!(allowDecimal ? /^-?\d+(\.\d+)?$/ : /^-?\d+$/).test(v)) {
		return `${label} must be a ${allowDecimal ? "number" : "whole number"}.`;
	}
	const n = Number(v);
	if (min != null && n < min) return `${label} must be at least ${min}.`;
	if (max != null && n > max) return `${label} must be at most ${max}.`;
	return null;
}

function passwordPolicyError(v) {
	v = v || "";
	const problems = [];
	if (v.length < 8) problems.push("at least 8 characters");
	if (!/[A-Z]/.test(v)) problems.push("1 uppercase letter");
	if (!/[0-9]/.test(v)) problems.push("1 number");
	if (!/[^A-Za-z0-9]/.test(v)) problems.push("1 special character");
	if (!problems.length) return null;
	return `Password must contain ${problems.join(", ")}.`;
}

function wirePasswordConfirm(pwEl, confirmEl, generateBtnEl, { required = false } = {}) {
	if (generateBtnEl) {
		generateBtnEl.addEventListener("click", async () => {
			const pw = generateStrongPassword();
			pwEl.type = "text";
			confirmEl.type = "text";
			pwEl.value = pw;
			confirmEl.value = pw;
			// Setting .value via JS is a plain property assignment -- unlike
			// real typing, it does NOT fire input/change, so a listener like
			// bindDirtyTracking's (container-level input/change) never sees
			// it. Dispatch both manually so a generated password is treated
			// exactly like a typed one -- including marking the Edit dialog
			// dirty/Save-enabled immediately.
			pwEl.dispatchEvent(new Event("input", { bubbles: true }));
			confirmEl.dispatchEvent(new Event("input", { bubbles: true }));
			// Copy to clipboard automatically -- same copyTextToClipboard()
			// helper/fallback-to-selection behavior clients.html's .ovpn copy
			// button already uses. This single fix covers all 4 dialogs that
			// call wirePasswordConfirm (Add User, Edit User, Reset Password,
			// Profile password-change) since they all funnel through here.
			const copied = await copyTextToClipboard(pw, pwEl);
			toast(copied
				? "Password generated and copied to clipboard."
				: "Password generated -- copy it now, it won't be shown again (automatic copy failed).", copied ? "success" : "error");
		});
	}
	function check() {
		const pw = pwEl.value;
		const confirm = confirmEl.value;
		if (!pw && !confirm) return required ? "Password is required." : null;
		// Policy is checked even when this pair is optional (e.g. Edit User's
		// "leave blank to keep current" reset) -- once a password IS being
		// set, it must comply, same as a brand-new account's would.
		const policyError = passwordPolicyError(pw);
		if (policyError) return policyError;
		if (pw !== confirm) return "Passwords don't match.";
		return null;
	}
	return { check };
}

// Human-formatted session duration for display -- e.g. "2h 14m", "45m",
// "12s". Mirrors vpn-status.py's fmt_duration() in spirit (both take
// seconds), but a shorter/denser format tuned for a table column rather
// than that script's terminal-table "0d 2h 14m" style: omits leading
// zero units instead of always showing all three, and drops down to
// seconds-only for sub-minute sessions rather than showing "0m".
// Human-formatted byte count -- e.g. "2.4GB", "512.0KB". Mirrors
// vpn-status.py's human_bytes() (same 1024-based steps/rounding), needed
// client-side here since session-history rows only carry the raw integer
// byte counts, unlike the live "connected" snapshot which already comes
// pre-formatted (bytes_received_h) from that same script.
function fmtBytes(n) {
	n = Number(n) || 0;
	const units = ["B", "KB", "MB", "GB", "TB", "PB"];
	let i = 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return i === 0 ? `${Math.trunc(n)}${units[i]}` : `${n.toFixed(1)}${units[i]}`;
}

/**
 * A small horizontal usage-percentage bar -- promoted here from
 * health.html's original `usageBar()` (same markup/CSS, `.usage-bar`/
 * `.usage-bar-fill` in style.css) since it's now also used for per-client
 * bandwidth-quota visibility (clients.html, my_vpn_profile.html), not just
 * host resource usage. `pct` null/undefined renders nothing (e.g. no quota
 * set -- "Unlimited" is rendered by the caller instead, not this helper).
 */
function usageBar(pct) {
	if (pct == null) return "";
	const level = pct >= 90 ? "usage-bar-critical" : pct >= 75 ? "usage-bar-warning" : "usage-bar-ok";
	return `<span class="usage-bar"><span class="usage-bar-fill ${level}" style="width:${Math.min(100, pct)}%"></span></span>`;
}

const OS_LABELS = { windows: "Win", linux: "Linux", mac: "macOS" };

// Current/Allocated/Remaining + a usage bar for one client's row -- "45GB /
// 100GB" with the shared usageBar() above (same visual language as Health's
// resource-usage bars). Clients with no quota configured show "Unlimited"
// instead of a bar, since there's no denominator to show progress against.
// Usage numbers reflect the last disconnect, not a live mid-session total
// (same "not live" caveat as the Manage Restrictions dialog's usage note).
// Shared by clients.html (All Clients table) and dashboard.html (Connected
// Now table) -- promoted here from clients.html so both can call it without
// duplicating the same markup/logic.
function bandwidthUsageHtml(policy, usage) {
	const quotaGb = policy && policy.bandwidth_monthly_gb;
	if (!quotaGb) return '<span class="muted">Unlimited</span>';
	const usedBytes = (usage && usage.bytes_used) || 0;
	const quotaBytes = quotaGb * 1024 ** 3;
	const pct = Math.round((usedBytes / quotaBytes) * 100);
	return `<div style="display:flex;align-items:center;gap:8px">
		<span class="mono" style="font-size:0.85rem;white-space:nowrap">${fmtBytes(usedBytes)} / ${quotaGb}GB</span>
		${usageBar(pct)}
	</div>`;
}

// Compact restriction-summary chips for one client's row -- only ever
// called for clients that actually have a policy, and only ever renders
// the chips for restrictions that are actually set, so a client with none
// produces nothing. Shared by clients.html and dashboard.html (see
// bandwidthUsageHtml above for why this moved here).
function restrictionChipsHtml(policy) {
	if (!policy) return "";
	const chips = [];
	const countries = policy.allowed_countries || [];
	if (countries.length) {
		const label = countries.join("/");
		chips.push(`<span class="restriction-chip chip-country" title="Restricted to: ${escapeHtml(countries.map(countryName).join(", "))}">${escapeHtml(label)}</span>`);
	}
	if (policy.allowed_os && policy.allowed_os.length) {
		const label = policy.allowed_os.map(o => OS_LABELS[o] || o).join("/");
		chips.push(`<span class="restriction-chip chip-os" title="Allowed OS: ${escapeHtml(label)}">${escapeHtml(label)} only</span>`);
	}
	if (policy.bandwidth_monthly_gb) {
		chips.push(`<span class="restriction-chip chip-bw" title="Monthly bandwidth quota: ${policy.bandwidth_monthly_gb}GB">${policy.bandwidth_monthly_gb}GB/mo</span>`);
	}
	const cities = policy.allowed_cities || [];
	if (cities.length) {
		chips.push(`<span class="restriction-chip chip-city" title="Restricted to cities: ${escapeHtml(cities.join(", "))}">${cities.length} cit${cities.length === 1 ? "y" : "ies"}</span>`);
	}
	const asns = policy.allowed_asns || [];
	if (asns.length) {
		chips.push(`<span class="restriction-chip chip-asn" title="Restricted to networks: ${escapeHtml(asns.join(", "))}">${asns.length} network${asns.length === 1 ? "" : "s"}</span>`);
	}
	const ips = policy.allowed_ips || [];
	if (ips.length) {
		chips.push(`<span class="restriction-chip chip-ip" title="Restricted to IPs: ${escapeHtml(ips.join(", "))}">${ips.length} IP${ips.length === 1 ? "" : "s"}</span>`);
	}
	if (!chips.length) return "";
	return `<div class="restriction-chips">${chips.join("")}</div>`;
}

function fmtDuration(totalSeconds) {
	const seconds = Math.max(0, Math.trunc(Number(totalSeconds) || 0));
	const d = Math.floor(seconds / 86400);
	const h = Math.floor((seconds % 86400) / 3600);
	const m = Math.floor((seconds % 3600) / 60);
	const s = seconds % 60;
	if (d > 0) return `${d}d ${h}h`;
	if (h > 0) return `${h}h ${m}m`;
	if (m > 0) return `${m}m ${s}s`;
	return `${s}s`;
}

// Formats an ISO timestamp using the app-wide Timezone/Clock Format
// settings (Settings page -> Localization; window.APP_TIMEZONE/
// APP_TIME_FORMAT are set in base.html from app_settings.timezone/
// time_format -- see config.py's APP_TIMEZONE docstring). Every timestamp
// this app stores/emits is already UTC; this only ever affects display,
// never storage. Falls back to the browser's own locale/timezone if the
// configured zone is somehow invalid (e.g. a typo saved outside the UI's
// own validation) rather than showing nothing.
function fmtTimestamp(iso) {
	if (!iso) return "—";
	const d = new Date(iso);
	if (isNaN(d)) return String(iso);
	const opts = {
		year: "numeric", month: "short", day: "2-digit",
		hour: "2-digit", minute: "2-digit", second: "2-digit",
		hour12: window.APP_TIME_FORMAT === "12h",
	};
	if (window.APP_TIMEZONE) opts.timeZone = window.APP_TIMEZONE;
	try {
		return new Intl.DateTimeFormat(undefined, opts).format(d);
	} catch (e) {
		return d.toLocaleString();
	}
}

function escapeHtml(s) {
	const div = document.createElement("div");
	div.textContent = s == null ? "" : String(s);
	return div.innerHTML;
}

// Mirrors app_settings.py's ACTIVE_THEME_IDS/resolve_active_theme exactly
// (same 10 ids, same "hour // 2 % 10" 2-hour-slot rotation, same local-time
// basis) -- the client-side half of applying a theme change immediately
// (see applyThemeImmediately below) without waiting for a server round-trip
// to know which theme "auto" currently resolves to.
const ACTIVE_THEME_IDS = [
	"constellation", "contour", "ingress", "cipher", "perimeter", "horizon",
	"lattice", "flux", "pulse", "relay",
];
function resolveActiveThemeClientSide(loginThemeSetting) {
	if (loginThemeSetting && loginThemeSetting !== "auto") return loginThemeSetting;
	const slot = Math.floor(new Date().getHours() / 2) % ACTIVE_THEME_IDS.length;
	return ACTIVE_THEME_IDS[slot];
}

/**
 * Stamps the resolved theme directly onto <html data-theme="...">, live,
 * on the currently-open page -- used by both the header quick-switch and
 * the Settings page's theme dropdown so a theme change is visible the
 * instant it's saved, no page reload needed (previously both round-tripped
 * via window.location.reload() purely to pick up the new data-theme
 * base.html renders server-side on the NEXT page load; the setting itself
 * was already saved immediately, only the visual effect was delayed).
 * Purely a DOM update -- the caller is still responsible for persisting
 * the choice via PATCH /api/settings.
 */
function applyThemeImmediately(loginThemeSetting) {
	document.documentElement.setAttribute("data-theme", resolveActiveThemeClientSide(loginThemeSetting));
}

/**
 * Header quick theme switcher (admin-only, see base.html's
 * .theme-quick-switch) -- lets an admin change the app's active theme
 * (login-page background + logged-in accent palette, see
 * app_settings.py's resolve_active_theme) without visiting the full
 * Settings page. Deliberately reuses the exact same PATCH /api/settings
 * `login_theme` field the Settings page dropdown writes to -- no second
 * mechanism. A no-op on any page that doesn't render the switch (non-admin
 * users), since it's gated on the element existing.
 */
// Display labels for the header switch's current-theme name -- mirrors
// app_settings.py's THEME_CHOICES labels (kept in sync manually, same as
// the panel's own hardcoded button labels in base.html, since this button
// needs to show a name INSTANTLY on page load, before any API round-trip).
const THEME_QUICK_LABELS = {
	auto: "Auto-rotate", constellation: "Constellation", contour: "Signal Contour",
	ingress: "Ingress Field", cipher: "Cipher Rain", perimeter: "Perimeter Grid", horizon: "Data Horizon",
	lattice: "Threat Lattice", flux: "Quantum Flux", pulse: "Uplink Pulse", relay: "Glass Relay",
};

/**
 * Header quick theme switcher (admin-only, see base.html's
 * .theme-quick-switch) -- lets an admin change the app's active theme
 * (login-page background + logged-in accent palette, see
 * app_settings.py's resolve_active_theme) without visiting the full
 * Settings page. Deliberately reuses the exact same PATCH /api/settings
 * `login_theme` field the Settings page dropdown writes to -- no second
 * mechanism. A no-op on any page that doesn't render the switch (non-admin
 * users), since it's gated on the element existing.
 *
 * Also keeps the button itself legible at a glance (request: "Display the
 * currently selected theme name... Provide a visual indicator... without
 * opening Settings"): the toggle shows the resolved theme's name plus a
 * colored dot (via #theme-quick-swatch, which just reads var(--accent) off
 * the live <html data-theme="...">, so it always matches whatever's
 * actually rendered), and the open panel marks the currently-SAVED setting
 * (not just the resolved one -- "auto" itself gets the checkmark when
 * that's what's saved, even though the resolved theme underneath it is
 * only one of the 6) with a checkmark plus an `.active` highlight.
 */
(function initThemeQuickSwitch() {
	const root = document.getElementById("theme-quick-switch");
	if (!root) return;
	const toggle = document.getElementById("theme-quick-toggle");
	const panel = document.getElementById("theme-quick-panel");
	const label = document.getElementById("theme-quick-label");

	// window.SAVED_LOGIN_THEME (base.html) is the raw setting as of the last
	// page render; kept in sync client-side after every successful save
	// below so a second change in the same page view doesn't need a reload.
	let savedTheme = window.SAVED_LOGIN_THEME || "auto";

	function updateQuickLabel() {
		label.textContent = THEME_QUICK_LABELS[savedTheme] || savedTheme;
	}
	function updatePanelActiveMarks() {
		panel.querySelectorAll(".theme-quick-option").forEach((btn) => {
			btn.classList.toggle("active", btn.dataset.themeValue === savedTheme);
		});
	}
	updateQuickLabel();
	updatePanelActiveMarks();

	// Exposed so settings.html's own theme dropdown -- a second place the
	// saved setting can change from, on the same page, without a reload --
	// can keep this header switch in sync immediately after its own save,
	// rather than the header only catching up on next navigation.
	window.refreshThemeQuickSwitch = (newSavedTheme) => {
		savedTheme = newSavedTheme || "auto";
		updateQuickLabel();
		updatePanelActiveMarks();
	};

	toggle.addEventListener("click", () => {
		const willOpen = panel.style.display !== "block";
		panel.style.display = willOpen ? "block" : "none";
		toggle.setAttribute("aria-expanded", String(willOpen));
	});
	document.addEventListener("click", (ev) => {
		if (!root.contains(ev.target)) {
			panel.style.display = "none";
			toggle.setAttribute("aria-expanded", "false");
		}
	});

	panel.querySelectorAll(".theme-quick-option").forEach((btn) => {
		btn.addEventListener("click", async () => {
			panel.style.display = "none";
			const themeValue = btn.dataset.themeValue;
			const previousTheme = document.documentElement.getAttribute("data-theme");
			const previousSaved = savedTheme;
			applyThemeImmediately(themeValue); // instant, no reload -- see this function's docstring
			savedTheme = themeValue;
			updateQuickLabel();
			updatePanelActiveMarks();
			try {
				await apiFetch("/api/settings", { method: "PATCH", body: { login_theme: themeValue } });
				window.SAVED_LOGIN_THEME = themeValue;
				toast("Theme updated.");
			} catch (e) {
				if (previousTheme) document.documentElement.setAttribute("data-theme", previousTheme); // roll back the optimistic apply -- the save itself failed
				savedTheme = previousSaved;
				updateQuickLabel();
				updatePanelActiveMarks();
				toast(e.message, "error");
			}
		});
	});
})();

/**
 * Mobile sidebar toggle (base.html's #sidebar-toggle / #sidebar /
 * #sidebar-backdrop) -- below the 860px breakpoint in style.css the
 * sidebar is a fixed off-canvas drawer; this just adds/removes the
 * `.open` class that CSS transition slides it in on. A no-op above that
 * breakpoint since the toggle button itself is display:none there, but
 * the listeners are harmless either way.
 */
(function initSidebarToggle() {
	const toggle = document.getElementById("sidebar-toggle");
	const sidebar = document.getElementById("sidebar");
	const backdrop = document.getElementById("sidebar-backdrop");
	if (!toggle || !sidebar || !backdrop) return;

	function closeSidebar() {
		sidebar.classList.remove("open");
		backdrop.classList.remove("open");
		toggle.setAttribute("aria-expanded", "false");
	}
	function openSidebar() {
		sidebar.classList.add("open");
		backdrop.classList.add("open");
		toggle.setAttribute("aria-expanded", "true");
	}

	toggle.addEventListener("click", () => {
		if (sidebar.classList.contains("open")) closeSidebar();
		else openSidebar();
	});
	backdrop.addEventListener("click", closeSidebar);
	// Closing on nav-link click (rather than leaving it open across a full
	// page navigation) matches the marketing/docs sites' own mobile menus --
	// the drawer's job is done once it's gotten you where you're going.
	sidebar.querySelectorAll("nav a").forEach((a) => a.addEventListener("click", closeSidebar));
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape") closeSidebar();
	});
})();

/**
 * Shared app-wide "(i)" info tooltip (see .info-tip in style.css) -- the
 * hover/keyboard-focus display is pure CSS (:hover/:focus-visible), so
 * this handler only exists for the tap case: touch devices don't fire
 * :hover reliably, so a tap toggles a `.tip-open` class instead (the CSS
 * shows the popover for that class too). One delegated listener covers
 * every .info-tip on every page, present or added later, with no per-page
 * wiring -- same "just works everywhere" shape as apiFetch/toast. Toggling
 * one tip closes any other that was left open by a previous tap, mirroring
 * the notif-bell/theme-quick-switch panels' own single-panel-open
 * convention above.
 */
document.addEventListener("click", (e) => {
	const tip = e.target.closest(".info-tip");
	document.querySelectorAll(".info-tip.tip-open").forEach((t) => {
		if (t !== tip) t.classList.remove("tip-open");
	});
	if (tip) {
		tip.classList.toggle("tip-open");
		e.preventDefault(); // .info-tip is a <button> -- stop it submitting a parent <form>
	}
});

/**
 * Notification bell (sidebar header) -- backs the merged QuotaNotification
 * + TicketNotification feed (routes/notifications.py). Polls
 * GET /api/notifications every 60s (much lower-frequency data than the
 * 10s dashboard-snapshot cadence elsewhere in this app -- neither a quota
 * crossing nor a ticket reply needs near-real-time visibility) plus once
 * on page load; updates the unread badge always, re-renders the list only
 * while the panel is open (no point rebuilding DOM the user can't see).
 * Same anchored-panel toggle shape as initThemeQuickSwitch above (plain
 * style.display, close on outside click) -- present on every
 * authenticated page since it's in base.html, not gated by role (every
 * account, including "User"-role self-service accounts, can have
 * notifications about its own quota/tickets). A notification with a
 * link_url (ticket events; quota ones have none) navigates there once
 * marked read -- see each item's click handler below.
 */
(function initNotificationBell() {
	const root = document.getElementById("notif-bell");
	if (!root) return;
	const toggle = document.getElementById("notif-bell-toggle");
	const panel = document.getElementById("notif-bell-panel");
	const badge = document.getElementById("notif-bell-badge");
	const listEl = document.getElementById("notif-bell-list");
	let lastNotifications = [];

	function renderList() {
		listEl.innerHTML = lastNotifications.length
			? lastNotifications.map((n) => `
				<div class="notif-item ${n.read_at ? "" : "unread"}" data-id="${n.id}" data-link="${n.link_url || ""}" style="${n.link_url ? "cursor:pointer" : ""}">
					<span class="notif-item-level ${n.level}">${n.level}</span>
					<div>${escapeHtml(n.message)}</div>
					<div class="notif-item-time">${fmtTimestamp(n.created_at)}</div>
				</div>`).join("")
			: '<p class="muted" style="padding:14px">No notifications.</p>';
		listEl.querySelectorAll(".notif-item").forEach((el) => {
			if (!el.classList.contains("unread") && !el.dataset.link) return;
			el.addEventListener("click", async () => {
				try {
					if (el.classList.contains("unread")) await apiFetch(`/api/notifications/${el.dataset.id}/read`, { method: "POST" });
					if (el.dataset.link) { window.location.href = el.dataset.link; return; }
					await refresh();
				} catch (e) { /* non-fatal -- the item just stays marked unread */ }
			});
		});
	}

	async function refresh() {
		try {
			const data = await apiFetch("/api/notifications");
			lastNotifications = data.notifications || [];
			badge.style.display = data.unread_count > 0 ? "" : "none";
			badge.textContent = data.unread_count > 99 ? "99+" : String(data.unread_count);
			if (panel.style.display === "block") renderList();
		} catch (e) { /* non-fatal -- bell just stays at its last-known state */ }
	}

	toggle.addEventListener("click", () => {
		const willOpen = panel.style.display !== "block";
		panel.style.display = willOpen ? "block" : "none";
		toggle.setAttribute("aria-expanded", String(willOpen));
		if (willOpen) renderList();
	});
	document.addEventListener("click", (ev) => {
		if (!root.contains(ev.target)) {
			panel.style.display = "none";
			toggle.setAttribute("aria-expanded", "false");
		}
	});
	document.getElementById("notif-bell-mark-all").addEventListener("click", async () => {
		try {
			await apiFetch("/api/notifications/read-all", { method: "POST" });
			await refresh();
		} catch (e) {
			toast(e.message, "error");
		}
	});

	refresh();
	setInterval(refresh, 60000);
})();

/**
 * Show/hide toggle for every password field app-wide -- login, forgot/reset
 * password, change-password, profile, and every password input in the Users
 * page's Add/Edit/Reset-Password dialogs. One pass over
 * `input[type="password"]` here rather than per-template wiring, so a new
 * password field added anywhere later gets the toggle for free with zero
 * extra markup -- same "just works everywhere" shape as the .info-tip
 * delegated handler above.
 *
 * Every match gets wrapped in a `.password-toggle-wrap` (position:relative)
 * so the toggle button can sit absolutely inside it without touching the
 * input's own layout role -- this matters for e.g. `.password-field-row`
 * (users.html's Reset Password dialog), where the input is itself a flex
 * item next to a "Generate" button: swapping in a wrapper div rather than
 * inserting the button as the input's own next sibling keeps that existing
 * flex pairing intact (see .password-toggle-wrap's `flex: 1` in style.css).
 * Runs once at script-load time, not on DOMContentLoaded -- this <script>
 * tag is the last thing base.html renders, after every block's markup
 * (including the dialogs below), so the DOM is already complete by the time
 * this line runs (same assumption every other top-level IIFE in this file
 * already makes).
 *
 * Toggling `type` between "password" and "text" never touches `name`,
 * `id`, `required`, `autocomplete`, or the field's current `value` --
 * those are unrelated attributes/properties, so nothing about what the
 * form submits changes because the toggle was clicked.
 */
(function initPasswordToggles() {
	const EYE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
	const EYE_OFF_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.3 20.3 0 0 1 5.06-6.06M9.9 4.24A10.4 10.4 0 0 1 12 4c7 0 11 8 11 8a20.28 20.28 0 0 1-3.22 4.44M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

	// Exposed globally (not just the forEach below) so code that builds a
	// password input AFTER this script has already run -- e.g.
	// passwordConfirmDialog()'s dynamically-created <dialog>, same pattern
	// as confirmDialog() -- can opt that field into the same show/hide
	// toggle instead of shipping a second, inconsistent password field.
	window.addPasswordToggle = function (input) {
		// Already wrapped (defensive -- guards against a future double-call
		// on the same input, e.g. a dialog re-opened without being removed).
		if (input.closest(".password-toggle-wrap")) return;

		const wrap = document.createElement("div");
		wrap.className = "password-toggle-wrap";
		input.parentNode.insertBefore(wrap, input);
		wrap.appendChild(input);

		const btn = document.createElement("button");
		btn.type = "button"; // never "submit" -- must not trigger the surrounding <form>
		btn.className = "password-toggle-btn";
		btn.setAttribute("aria-label", "Show password");
		btn.innerHTML = EYE_ICON;
		wrap.appendChild(btn);

		btn.addEventListener("click", () => {
			const showing = input.type === "text";
			input.type = showing ? "password" : "text";
			btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
			btn.innerHTML = showing ? EYE_ICON : EYE_OFF_ICON;
		});
	};

	document.querySelectorAll('input[type="password"]').forEach(window.addPasswordToggle);

	// A handful of templates (users.html's Add/Edit User dialogs) reset a
	// password input's `.type` back to "password" straight from their own
	// form-reset code, bypassing the click handler above entirely -- doing
	// that with a bare `el.type = "password"` would leave the toggle button
	// showing its "hide"/eye-slash state (and stale aria-label) even though
	// the field itself is masked again. Exposed globally so those reset
	// paths can call this instead of touching `.type` directly, keeping the
	// button's icon/label in sync with the field's actual visibility.
	window.resetPasswordVisibility = function (input) {
		if (!input) return;
		input.type = "password";
		const btn = input.closest(".password-toggle-wrap")?.querySelector(".password-toggle-btn");
		if (!btn) return;
		btn.setAttribute("aria-label", "Show password");
		btn.innerHTML = EYE_ICON;
	};
})();
