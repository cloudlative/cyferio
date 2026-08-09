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
 * Usage:
 *   const phone = createPhoneInput(document.getElementById("mount"));
 *   phone.setValue(u.phone);       // parses "+923001234567" -> ("+92", "3001234567")
 *   phone.getValue();              // -> "+923001234567", or "" if local number is blank
 *   phone.getLocalInputEl();       // the local-number <input>, for attaching blur/input validation
 */
function createPhoneInput(root) {
	root.classList.add("phone-input");
	root.innerHTML = `
		<select class="phone-dial-select" aria-label="Country code">
			<option value="">+‎ —</option>
			${DIAL_CODES.map(([name, dial]) => `<option value="${dial}">${dial} ${escapeHtml(name)}</option>`).join("")}
		</select>
		<input type="text" class="phone-local-input" inputmode="tel" placeholder="Local number">`;
	const dialSelect = root.querySelector(".phone-dial-select");
	const localInput = root.querySelector(".phone-local-input");

	return {
		setValue(phone) {
			phone = (phone || "").trim();
			if (!phone) {
				dialSelect.value = "";
				localInput.value = "";
				return;
			}
			const match = _DIAL_CODES_BY_LENGTH.find(([, dial]) => phone.startsWith(dial));
			if (match) {
				dialSelect.value = match[1];
				localInput.value = phone.slice(match[1].length);
			} else {
				// Doesn't cleanly match any known dial code (e.g. a legacy
				// value entered before this UI existed) -- don't crash or
				// guess, just show it raw with no dial code preselected, per
				// the task's documented fallback.
				dialSelect.value = "";
				localInput.value = phone;
			}
		},
		getValue() {
			const local = localInput.value.trim().replace(/[^\d]/g, "");
			if (!local) return "";
			const dial = dialSelect.value || "";
			return dial + local;
		},
		getLocalInputEl() {
			return localInput;
		},
		reset() {
			dialSelect.value = "";
			localInput.value = "";
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

// Human-formatted session duration for display -- e.g. "2h 14m", "45m",
// "12s". Mirrors vpn-status.py's fmt_duration() in spirit (both take
// seconds), but a shorter/denser format tuned for a table column rather
// than that script's terminal-table "0d 2h 14m" style: omits leading
// zero units instead of always showing all three, and drops down to
// seconds-only for sub-minute sessions rather than showing "0m".
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
(function initThemeQuickSwitch() {
	const root = document.getElementById("theme-quick-switch");
	if (!root) return;
	const toggle = document.getElementById("theme-quick-toggle");
	const panel = document.getElementById("theme-quick-panel");

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
			try {
				await apiFetch("/api/settings", { method: "PATCH", body: { login_theme: btn.dataset.themeValue } });
				toast("Theme updated.");
				window.location.reload();
			} catch (e) {
				toast(e.message, "error");
			}
		});
	});
})();
