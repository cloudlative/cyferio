// Shared helpers used by every page's inline <script> block.

function toast(message, kind = "success") {
	const container = document.getElementById("toast-container");
	const el = document.createElement("div");
	el.className = `toast ${kind}`;
	el.textContent = message;
	container.appendChild(el);
	setTimeout(() => el.remove(), 5000);
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
	return res.json();
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

function escapeHtml(s) {
	const div = document.createElement("div");
	div.textContent = s == null ? "" : String(s);
	return div.innerHTML;
}
