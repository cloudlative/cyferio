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
 * Shows a toast notification. Auto-dismisses after 4s, or immediately via
 * its "×" close button. Multiple toasts stack (newest at the bottom,
 * pushing older ones up) rather than replacing each other.
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
	setTimeout(() => el.remove(), 4000);
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

// A small set of colors reused across every chart on the site, drawn from
// the same accent/status palette already defined in style.css (:root
// custom properties) so charts never introduce a clashing color scheme.
const CHART_COLORS = [
	"#6366f1", "#22d3ee", "#f59e0b", "#fb7185", "#34d399",
	"#818cf8", "#fbbf24", "#f43f5e", "#2dd4bf", "#a78bfa",
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
		const circle = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
			stroke="${CHART_COLORS[i % CHART_COLORS.length]}" stroke-width="${thickness}"
			stroke-dasharray="${dash} ${circumference - dash}"
			stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})">
			<title>${escapeHtml(e.label)}: ${e.value} (${(fraction * 100).toFixed(1)}%)</title>
		</circle>`;
		offset += dash;
		return circle;
	}).join("");

	const legend = entries.map((e, i) => `
		<div style="display:flex;align-items:center;gap:8px;font-size:0.85rem;">
			<span style="width:10px;height:10px;border-radius:3px;background:${CHART_COLORS[i % CHART_COLORS.length]};flex:none"></span>
			<span style="flex:1">${escapeHtml(e.label)}</span>
			<span class="muted mono">${e.value}</span>
		</div>`).join("");

	mountEl.innerHTML = `
		<div style="display:flex;gap:28px;align-items:center;flex-wrap:wrap">
			<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Donut chart">
				${arcs}
				<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="middle"
					fill="var(--text)" font-size="${size * 0.13}" font-weight="800">${total}</text>
			</svg>
			<div style="display:flex;flex-direction:column;gap:8px;min-width:160px;flex:1">${legend}</div>
		</div>`;
}

function escapeHtml(s) {
	const div = document.createElement("div");
	div.textContent = s == null ? "" : String(s);
	return div.innerHTML;
}
