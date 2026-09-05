/*
 * spa.js -- single-window shell navigation.
 *
 * Deliberately NOT a frontend framework, and deliberately does not
 * introduce any new backend routes. Every page this loader can
 * navigate to is still a completely normal, full, real,
 * server-rendered HTML page at its real URL -- direct navigation,
 * refresh, and bookmarks all keep working exactly as before, and
 * every page still works correctly with zero JavaScript at all. What
 * this adds is purely a progressive enhancement: when a click on an
 * internal link happens WITHIN an already-loaded shell page, this
 * fetches that same real URL, pulls out just the #view-root content
 * (everything a page's {% block view_content %} renders), and swaps
 * it into the current page's #view-root instead of letting the
 * browser do a full navigation -- so the sidebar/topbar chrome never
 * flickers or reloads, per the "persistent application shell" /
 * "should not appear to leave the application" requirement.
 *
 * Three things this has to get right, each documented at the point
 * it's handled below: re-executing each view's own <script> content
 * without colliding with previously-loaded views' top-level
 * declarations; not silently swallowing a session-expired redirect to
 * /login; and cleaning up anything a view left running (see
 * app.js's onViewLeave/runViewCleanup) before tearing its DOM down.
 */
(function () {
  const viewRoot = document.getElementById('view-root');
  if (!viewRoot) return; // pages outside the shell (login) don't use this at all

  const sidebar = document.querySelector('.sidebar');
  const scrim = document.querySelector('.sidebar-scrim');
  const navToggle = document.querySelector('.mobile-nav-toggle');
  const navProgress = document.querySelector('.nav-progress');
  const breadcrumbEl = document.getElementById('breadcrumb-text');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function isSpaLink(a) {
    if (!a || a.target === '_blank' || a.hasAttribute('download') || a.dataset.noSpa !== undefined) return false;
    const href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('http:') || href.startsWith('https:') || href.startsWith('//')) return false;
    return true;
  }

  function setActiveNav(url) {
    const path = new URL(url, window.location.origin).pathname;
    document.querySelectorAll('.nav-item').forEach((el) => {
      const hrefAttr = el.getAttribute('href');
      if (!hrefAttr) return;
      const linkPath = new URL(hrefAttr, window.location.origin).pathname;
      el.classList.toggle('active', linkPath === path);
    });
  }

  function closeMobileNav() {
    if (sidebar) sidebar.classList.remove('is-open');
    if (scrim) scrim.classList.remove('is-visible');
  }

  async function navigateTo(url, { push = true } = {}) {
    if (navProgress) {
      navProgress.classList.remove('is-done');
      navProgress.classList.add('is-active');
    }

    let res;
    try {
      res = await fetch(url, { credentials: 'same-origin' });
    } catch (err) {
      // Network hiccup: fall back to a real navigation rather than
      // leave the user stuck on a half-updated view with no feedback.
      window.location.href = url;
      return;
    }

    // A session expiring mid-visit means every page route redirects to
    // /login (server-side, via RedirectResponse) -- fetch() follows
    // that redirect transparently, so res.url ends up being /login
    // even though `url` was e.g. /tacacs/devices. Grafting a login
    // form's markup into the app shell would be actively confusing;
    // a real navigation lets the normal "you're logged out" flow work.
    if (res.url && new URL(res.url, window.location.origin).pathname === '/login') {
      window.location.href = res.url;
      return;
    }
    if (!res.ok) {
      window.location.href = url;
      return;
    }

    const html = await res.text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const newRoot = doc.getElementById('view-root');
    if (!newRoot) {
      // Fetched something that isn't a shell page -- shouldn't happen
      // for an internal nav link, but fail safe with a real navigation
      // rather than render nothing.
      window.location.href = url;
      return;
    }

    if (window.AAAPlatform && AAAPlatform.runViewCleanup) {
      AAAPlatform.runViewCleanup();
    }

    if (!reduceMotion) {
      viewRoot.classList.add('is-leaving');
      await new Promise((resolve) => setTimeout(resolve, 120));
    }

    document.title = doc.title;
    if (breadcrumbEl) breadcrumbEl.textContent = newRoot.dataset.breadcrumb || '';

    viewRoot.innerHTML = newRoot.innerHTML;
    viewRoot.classList.remove('is-leaving');
    // Re-trigger the CSS fade-in (the animation only plays once per
    // element unless the animation is removed and re-applied).
    void viewRoot.offsetWidth;
    viewRoot.style.animation = 'none';
    void viewRoot.offsetWidth;
    viewRoot.style.animation = '';

    // history.pushState() runs BEFORE re-executing the new page's own
    // inline scripts, deliberately -- any page that reads
    // window.location.pathname during its own initialization (e.g. to
    // extract a dynamic URL segment like a device or job ID) needs the
    // URL to already reflect where it's actually navigating TO, not
    // wherever the user was navigating FROM. Doing this after script
    // execution (the order this was originally written in) meant
    // every such page's own script would read the OLD path on every
    // SPA transition, extracting the wrong ID from it every time and
    // failing to find its own data -- correct only on a hard refresh
    // or direct URL visit, since only those cases involve a real page
    // load where the URL was already correct from the start.
    if (push) history.pushState({ spa: true }, '', url);

    // Re-execute the fetched page's own inline scripts -- scoped
    // specifically to #view-scripts-container (see app_shell.html's
    // comment on that element for why: a broader `script:not([src])`
    // selector here would ALSO re-match and re-run the shell-level
    // scripts that are supposed to execute exactly once, at the real
    // initial page load, most importantly the daemon-status poller --
    // re-running that on every single navigation would spin up a new
    // orphaned setInterval each time, which is exactly the resource
    // leak onViewLeave/runViewCleanup exists to prevent, just arrived
    // at via a different bug. Each matched script is wrapped in its
    // own IIFE before being injected as a brand-new <script> element:
    // appending a script element runs it synchronously, and the
    // wrapper means a `let`/`const` declared at the top of one view's
    // script (e.g. `let currentRules = []`) can never collide with a
    // same-named declaration the next time a script runs -- without
    // it, a second execution of the same or a different view's script
    // re-declaring the same top-level `let`/`const` would throw
    // "already been declared" and silently break navigation.
    const inlineScripts = Array.from(doc.querySelectorAll('#view-scripts-container script:not([src])'));
    for (const original of inlineScripts) {
      const fresh = document.createElement('script');
      fresh.textContent = '(function(){\n' + original.textContent + '\n})();';
      document.body.appendChild(fresh);
      document.body.removeChild(fresh);
    }

    setActiveNav(url);
    closeMobileNav();
    // Sidebar-specific reactions (auto-expanding the active item's
    // section) live outside this file on purpose -- spa.js itself
    // has no concept of "sections"; see app_shell.html's own listener
    // for this event.
    document.dispatchEvent(new CustomEvent('spa:navigated', { detail: { url } }));

    if (navProgress) {
      navProgress.classList.remove('is-active');
      navProgress.classList.add('is-done');
      setTimeout(() => navProgress.classList.remove('is-done'), 300);
    }

    window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  document.addEventListener('click', (event) => {
    const a = event.target.closest('a');
    if (!isSpaLink(a)) return;
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigateTo(a.getAttribute('href'));
  });

  window.addEventListener('popstate', () => {
    navigateTo(window.location.pathname + window.location.search, { push: false });
  });

  if (navToggle && sidebar) {
    navToggle.addEventListener('click', () => {
      sidebar.classList.toggle('is-open');
      if (scrim) scrim.classList.toggle('is-visible');
    });
  }
  if (scrim) {
    scrim.addEventListener('click', closeMobileNav);
  }

  // Keep client-side active-nav state in sync with the server-rendered
  // initial state too (sidebar.html already computes this correctly
  // server-side on first load as a no-JS-required fallback; this just
  // means both agree from the very first paint onward).
  setActiveNav(window.location.href);
  document.dispatchEvent(new CustomEvent('spa:navigated', { detail: { url: window.location.href } }));
})();
