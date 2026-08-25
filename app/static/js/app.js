/*
 * Shared front-end utilities. Kept deliberately small in Phase 1 --
 * each page's own inline <script> block does its specific work, but
 * anything state-changing (POST/PUT/DELETE) should route through
 * authedFetch() so the CSRF header (spec section 35) is never
 * forgotten as new modules are added in later phases.
 */
window.AAAPlatform = (function () {
  function readCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }

  function authedFetch(url, options = {}) {
    const csrf = readCookie('aaa_platform_csrf');
    const headers = Object.assign({}, options.headers || {});
    if (csrf && options.method && options.method.toUpperCase() !== 'GET') {
      headers['X-CSRF-Token'] = csrf;
    }
    return fetch(url, Object.assign({}, options, { headers, credentials: 'same-origin' }));
  }

  function toast(message, kind = 'success') {
    const el = document.createElement('div');
    el.className = 'toast toast-' + kind;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  }

  function wireLogout() {
    const btn = document.getElementById('logout-btn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      await authedFetch('/api/auth/logout', { method: 'POST' });
      window.location.href = '/login';
    });
  }

  document.addEventListener('DOMContentLoaded', wireLogout);

  /*
   * Autofocus the first text-like field inside a modal the moment it
   * becomes visible (its .modal-backdrop's `hidden` attribute is
   * removed) -- one observer covers every modal on every page,
   * present or future, with zero per-page changes needed. Attached
   * once, to document.body, with subtree:true: since spa.js only ever
   * replaces #view-root's INNER content (document.body itself is
   * never swapped), a single observer set up at the real initial page
   * load keeps correctly seeing newly-swapped-in modals across every
   * later in-app navigation too, with no need to re-attach anything.
   */
  function focusFirstModalInput(backdrop) {
    const modal = backdrop.querySelector('.modal');
    if (!modal) return;
    const selector = 'input:not([type="hidden"]):not([type="checkbox"]):not([disabled]), textarea:not([disabled])';
    const candidate = modal.querySelector(selector);
    if (!candidate) return;
    // Let the browser finish applying the visibility change before
    // focusing -- focusing in the same tick as removing `hidden` can
    // silently no-op on an element still transitioning into a
    // focusable state.
    requestAnimationFrame(() => candidate.focus());
  }

  const modalAutofocusObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type !== 'attributes' || m.attributeName !== 'hidden') continue;
      const el = m.target;
      if (!(el instanceof HTMLElement) || !el.classList.contains('modal-backdrop')) continue;
      if (!el.hidden) focusFirstModalInput(el);
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    modalAutofocusObserver.observe(document.body, { attributes: true, attributeFilter: ['hidden'], subtree: true });
  });

  /*
   * View-lifecycle cleanup, needed because of the single-window shell
   * (spa.js): navigating between views swaps #view-root's content via
   * innerHTML rather than a real page load, so anything a view sets up
   * that OUTLIVES its own DOM (setInterval polling being the main
   * case -- e.g. the dashboard's status refresh) would otherwise keep
   * running in the background against elements that no longer exist,
   * throwing on every tick and silently leaking timers with every
   * visit to that view. A page that starts an interval/timeout/
   * subscription registers a cleanup callback here; spa.js calls
   * runViewCleanup() immediately before swapping to the next view.
   * Pages that don't use this (most of them -- anything without a
   * setInterval) don't need to know it exists.
   */
  let viewCleanupFns = [];

  function onViewLeave(fn) {
    viewCleanupFns.push(fn);
  }

  function runViewCleanup() {
    viewCleanupFns.forEach((fn) => {
      try { fn(); } catch (err) { /* a cleanup failing must never block navigation */ }
    });
    viewCleanupFns = [];
  }

  /*
   * Reusable "create X without leaving this form" pattern. Used by
   * Devices (quick-add a Device Group), Users (quick-add a TACACS+
   * Group), and Groups (quick-add a Policy) -- all three only need a
   * name and an optional description, and the target APIs already
   * apply sensible server-side defaults for everything else (a
   * quick-added Policy comes back priv-lvl 1, deny-by-default --
   * secure by default, refine later on its own page), so one generic
   * helper covers every case rather than three near-duplicate blocks.
   *
   * Deliberately an inline expand/collapse panel within the SAME
   * modal, not a second stacked modal -- avoids backdrop/focus/
   * z-index complexity for a payoff that would be mostly cosmetic.
   *
   * ids: { toggleBtn, panel, nameInput, descInput, errorBox,
   *        createBtn, cancelBtn, select }
   * apiEndpoint: e.g. '/api/device-groups'
   * refreshOptions: async function that re-populates `select`'s
   *   <option> list from the server (the page already has one of
   *   these for initial load; quick-add just calls it again).
   */
  function setupQuickAdd(ids, apiEndpoint, refreshOptions) {
    const toggleBtn = document.getElementById(ids.toggleBtn);
    const panel = document.getElementById(ids.panel);
    const nameInput = document.getElementById(ids.nameInput);
    const descInput = document.getElementById(ids.descInput);
    const errorBox = document.getElementById(ids.errorBox);
    const createBtn = document.getElementById(ids.createBtn);
    const cancelBtn = document.getElementById(ids.cancelBtn);
    const select = document.getElementById(ids.select);

    if (!toggleBtn || !panel || !select) return; // page doesn't use this pattern

    function closePanel() {
      panel.hidden = true;
      errorBox.hidden = true;
    }

    toggleBtn.addEventListener('click', () => {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) {
        nameInput.value = '';
        descInput.value = '';
        errorBox.hidden = true;
        nameInput.focus();
      }
    });

    cancelBtn.addEventListener('click', closePanel);

    createBtn.addEventListener('click', async () => {
      errorBox.hidden = true;
      const name = nameInput.value.trim();
      if (!name) {
        errorBox.textContent = 'Name is required.';
        errorBox.hidden = false;
        return;
      }

      createBtn.disabled = true;
      try {
        const res = await authedFetch(apiEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, description: descInput.value.trim() || null }),
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          errorBox.textContent = (body.detail && typeof body.detail === 'string')
            ? body.detail
            : 'Could not create it -- check the name and try again.';
          errorBox.hidden = false;
          return;
        }

        const created = await res.json();
        await refreshOptions();
        select.value = created.id;
        closePanel();
        toast(`"${created.name}" created.`);
      } finally {
        createBtn.disabled = false;
      }
    });
  }

  return { readCookie, authedFetch, toast, setupQuickAdd, onViewLeave, runViewCleanup };
})();
