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

  /*
   * Global ESC-to-close for every .modal-backdrop, with unsaved-
   * changes protection -- scoped deliberately to Escape only, not
   * the existing click-outside-to-close handlers each modal already
   * has (those stay exactly as they are; this doesn't touch them).
   *
   * "Dirty" tracking: any input/change event bubbling up from inside
   * a currently-visible modal marks it dirty; a MutationObserver on
   * `document.body` (subtree: true, so it automatically covers
   * modal-backdrops added later by SPA view navigation without
   * needing to re-attach anything) resets that flag the moment a
   * modal's `hidden` attribute is cleared -- i.e. every time a modal
   * is freshly opened, regardless of which page's own openXModal()
   * function did it.
   *
   * A custom shared confirm modal (#unsaved-changes-modal-backdrop,
   * in app_shell.html) is used instead of the native confirm() --
   * native dialogs cannot have a custom default/focused button, and
   * the safe default here (defaulting to keep-editing, not silently
   * discarding real edits) needs one.
   */
  (function setupEscToClose() {
    const dirtyModals = new WeakSet();

    function isRealModal(el) {
      return el && el.classList && el.classList.contains('modal-backdrop')
        && el.id !== 'unsaved-changes-modal-backdrop';
    }

    document.addEventListener('input', (e) => {
      const backdrop = e.target.closest && e.target.closest('.modal-backdrop');
      if (isRealModal(backdrop) && !backdrop.hidden) dirtyModals.add(backdrop);
    }, true);
    document.addEventListener('change', (e) => {
      const backdrop = e.target.closest && e.target.closest('.modal-backdrop');
      if (isRealModal(backdrop) && !backdrop.hidden) dirtyModals.add(backdrop);
    }, true);

    const observer = new MutationObserver((mutations) => {
      mutations.forEach((m) => {
        if (m.attributeName === 'hidden' && isRealModal(m.target) && !m.target.hidden) {
          dirtyModals.delete(m.target); // just opened (or re-opened) -- start clean
        }
      });
    });
    observer.observe(document.body, { attributes: true, attributeFilter: ['hidden'], subtree: true });

    function topVisibleModal() {
      const visible = Array.from(document.querySelectorAll('.modal-backdrop')).filter((el) => isRealModal(el) && !el.hidden);
      return visible.length ? visible[visible.length - 1] : null;
    }

    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;

      const unsavedModal = document.getElementById('unsaved-changes-modal-backdrop');
      if (unsavedModal && !unsavedModal.hidden) {
        // Escape on the confirm prompt itself acts like "Keep
        // editing" -- the same safe default as its focused button,
        // not another level of confirmation.
        unsavedModal.hidden = true;
        return;
      }

      const target = topVisibleModal();
      if (!target) return;

      if (dirtyModals.has(target) && unsavedModal) {
        unsavedModal.hidden = false;
      } else {
        target.hidden = true;
      }
    });

    const keepEditingBtn = document.getElementById('unsaved-changes-keep-editing-btn');
    const discardBtn = document.getElementById('unsaved-changes-discard-btn');
    if (keepEditingBtn) {
      keepEditingBtn.addEventListener('click', () => {
        document.getElementById('unsaved-changes-modal-backdrop').hidden = true;
      });
    }
    if (discardBtn) {
      discardBtn.addEventListener('click', () => {
        document.getElementById('unsaved-changes-modal-backdrop').hidden = true;
        // Re-query for the currently-visible real modal AT CLICK TIME,
        // rather than relying on a value captured earlier when Escape
        // was first pressed. The dirty modal stays visible (just
        // overlaid) for the entire time this confirm prompt is
        // showing, so this is provably correct regardless of any
        // staleness a captured-earlier reference could develop --
        // deliberately removed the earlier `pendingCloseTarget`
        // closure variable entirely rather than trust it, after a
        // real report that "Discard and close" did nothing even after
        // many clicks and this project's own testing could not
        // conclusively reproduce a root cause to fix more narrowly.
        const target = topVisibleModal();
        if (target) {
          target.hidden = true;
          dirtyModals.delete(target);
        }
      });
    }
  })();

  let openContextMenuEl = null;

  function closeContextMenu() {
    if (openContextMenuEl) {
      openContextMenuEl.remove();
      openContextMenuEl = null;
    }
  }

  // Shared right-click context menu, so every page (Devices, Users,
  // Groups) gets identical behavior instead of three separate
  // implementations. `items` is an array of either a real action --
  // {label, onClick, danger?: bool} -- or the literal string
  // 'separator' for a visual divider. `onClick` receives no
  // arguments; the caller's own closure already has whatever row data
  // it needs. Positioned to stay on-screen even when the click is
  // near the window's right/bottom edge, dismissed on an outside
  // click, Escape, or scroll -- never left orphaned on the page.
  function showContextMenu(x, y, items) {
    closeContextMenu();
    const menu = document.createElement('div');
    menu.className = 'context-menu';
    menu.setAttribute('role', 'menu');
    items.forEach((item) => {
      if (item === 'separator') {
        const sep = document.createElement('div');
        sep.className = 'context-menu-separator';
        menu.appendChild(sep);
        return;
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'context-menu-item' + (item.danger ? ' context-menu-item-danger' : '');
      btn.textContent = item.label;
      btn.addEventListener('click', () => {
        closeContextMenu();
        item.onClick();
      });
      menu.appendChild(btn);
    });
    document.body.appendChild(menu);

    const rect = menu.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - rect.width - 8);
    const top = Math.min(y, window.innerHeight - rect.height - 8);
    menu.style.left = `${Math.max(8, left)}px`;
    menu.style.top = `${Math.max(8, top)}px`;
    openContextMenuEl = menu;
  }

  document.addEventListener('click', (e) => {
    if (openContextMenuEl && !openContextMenuEl.contains(e.target)) closeContextMenu();
  });
  document.addEventListener('contextmenu', (e) => {
    // A right-click elsewhere on the page (not on a row that opens
    // its own menu) closes whatever menu is already open, rather than
    // leaving a stale one floating while a new native menu also
    // appears.
    if (openContextMenuEl && !e.defaultPrevented) closeContextMenu();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && openContextMenuEl) closeContextMenu();
  });
  window.addEventListener('scroll', closeContextMenu, true);

  return { readCookie, authedFetch, toast, setupQuickAdd, onViewLeave, runViewCleanup, showContextMenu };
})();
