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
 * Shows a toast notification. Auto-dismisses after 3s, or immediately via
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
	setTimeout(() => el.remove(), 3000);
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
 */
function createMultiselectDropdown(root, { placeholder = "Select…", disabled = false } = {}) {
	root.classList.add("ms-dropdown");
	root.innerHTML = `
		<button type="button" class="ms-toggle"${disabled ? " disabled" : ""}>
			<span class="ms-toggle-label">${escapeHtml(placeholder)}</span>
			<span class="ms-toggle-caret">▾</span>
		</button>
		<div class="ms-panel"></div>`;
	if (disabled) root.classList.add("ms-disabled");

	const toggle = root.querySelector(".ms-toggle");
	const toggleLabel = root.querySelector(".ms-toggle-label");
	const panel = root.querySelector(".ms-panel");
	let options = [];
	let selected = new Set();

	function refreshLabel() {
		if (selected.size === 0) {
			toggleLabel.textContent = placeholder;
			toggleLabel.classList.add("muted");
		} else {
			const names = options.filter(o => selected.has(o.id)).map(o => o.label);
			toggleLabel.textContent = names.length <= 2 ? names.join(", ") : `${names.length} teams selected`;
			toggleLabel.classList.remove("muted");
		}
	}

	function renderPanel() {
		panel.innerHTML = options.length === 0
			? '<div class="ms-empty muted">No teams yet.</div>'
			: options.map(o => `
				<label class="ms-option">
					<input type="checkbox" value="${o.id}" ${selected.has(o.id) ? "checked" : ""}>
					<span>${escapeHtml(o.label)}</span>
				</label>`).join("");
		panel.querySelectorAll('input[type="checkbox"]').forEach(cb => {
			cb.addEventListener("change", () => {
				const id = Number(cb.value);
				if (cb.checked) selected.add(id); else selected.delete(id);
				refreshLabel();
			});
		});
	}

	toggle.addEventListener("click", () => {
		if (disabled) return;
		const willOpen = !panel.classList.contains("open");
		document.querySelectorAll(".ms-panel.open").forEach(p => p.classList.remove("open"));
		if (willOpen) panel.classList.add("open");
	});
	document.addEventListener("click", (ev) => {
		if (!root.contains(ev.target)) panel.classList.remove("open");
	});

	return {
		setOptions(opts) {
			options = opts;
			renderPanel();
			refreshLabel();
		},
		setSelected(ids) {
			selected = new Set((ids || []).map(Number));
			renderPanel();
			refreshLabel();
		},
		getSelected() {
			return [...selected];
		},
		reset() {
			selected = new Set();
			renderPanel();
			refreshLabel();
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

function escapeHtml(s) {
	const div = document.createElement("div");
	div.textContent = s == null ? "" : String(s);
	return div.innerHTML;
}
