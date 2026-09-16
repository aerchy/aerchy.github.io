/* =========================================================================
   Custom UI animations for the blog — smooth & subtle.
   All motion respects prefers-reduced-motion. Pure vanilla JS, no deps.
   ========================================================================= */
(function () {
  'use strict';

  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var finePointer = window.matchMedia('(pointer: fine)').matches;
  var lerp = function (a, b, t) { return a + (b - a) * t; };
  var clamp = function (v, min, max) { return v < min ? min : v > max ? max : v; };

  /* ---------------------------------------------------------------------
     1) Page transition — fade out on internal navigation, fade in on load
     --------------------------------------------------------------------- */
  (function pageTransition() {
    // fade-in handled by CSS (.page-fade on body). Mark ready to trigger it.
    document.documentElement.classList.add('anim-ready');

    if (reduce) return;

    function isInternalNav(a) {
      if (!a) return false;
      if (a.target && a.target !== '_self') return false;
      if (a.hasAttribute('download')) return false;
      if (a.getAttribute('rel') === 'external') return false;
      if (a.dataset && a.dataset.bsToggle) return false;     // collapse/toggle triggers
      if (a.classList.contains('popup') || a.classList.contains('img-link')) return false; // lightbox
      var href = a.getAttribute('href');
      if (!href) return false;
      if (href[0] === '#') return false;
      // let the browser handle Text Fragment links natively (search results),
      // otherwise the :~:text= highlight/scroll gets dropped
      if (href.indexOf(':~:') !== -1) return false;
      if (/^(mailto:|tel:|javascript:)/i.test(href)) return false;
      var url;
      try { url = new URL(a.href, location.href); } catch (e) { return false; }
      if (url.origin !== location.origin) return false;
      // same page (just a hash / query on current path) -> let browser handle
      if (url.pathname === location.pathname && url.hash) return false;
      return true;
    }

    document.addEventListener('click', function (e) {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey ||
          e.shiftKey || e.altKey) return;
      var a = e.target.closest && e.target.closest('a[href]');
      if (!isInternalNav(a)) return;
      e.preventDefault();
      var dest = a.href;
      document.body.classList.add('is-leaving');
      window.setTimeout(function () { window.location.href = dest; }, 240);
    }, false);

    // restore visibility when navigating back via bfcache
    window.addEventListener('pageshow', function (ev) {
      if (ev.persisted) document.body.classList.remove('is-leaving');
    });
  })();

  /* ---------------------------------------------------------------------
     3) Subtle 3D tilt on the home cards (parallax toward the cursor)
     --------------------------------------------------------------------- */
  (function cardTilt() {
    if (reduce || !finePointer) return;
    var cards = document.querySelectorAll('.v-card');
    if (!cards.length) return;
    var MAX = 5; // degrees

    cards.forEach(function (card) {
      var frame = null;
      var settle = null;
      function onEnter() {
        // Promote to its own compositor layer BEFORE any transform is applied,
        // so the image doesn't re-rasterize (flash) on the first move.
        if (settle) { clearTimeout(settle); settle = null; }
        card.style.willChange = 'transform';
      }
      function onMove(e) {
        var r = card.getBoundingClientRect();
        var px = (e.clientX - r.left) / r.width;   // 0..1
        var py = (e.clientY - r.top) / r.height;   // 0..1
        var ry = clamp((px - 0.5) * 2 * MAX, -MAX, MAX);
        var rx = clamp((0.5 - py) * 2 * MAX, -MAX, MAX);
        if (frame) cancelAnimationFrame(frame);
        frame = requestAnimationFrame(function () {
          card.style.transform =
            'perspective(950px) rotateX(' + rx.toFixed(2) + 'deg) rotateY(' +
            ry.toFixed(2) + 'deg) translateY(-4px)';
        });
      }
      function onLeave() {
        if (frame) cancelAnimationFrame(frame);
        frame = null;
        card.style.transform = '';
        // drop the layer only AFTER the ease-back finishes, so leaving doesn't
        // re-rasterize mid-animation (which looked like a refresh)
        if (settle) clearTimeout(settle);
        settle = setTimeout(function () { card.style.willChange = 'auto'; }, 320);
      }
      card.addEventListener('pointerenter', onEnter);
      card.addEventListener('pointermove', onMove, { passive: true });
      card.addEventListener('pointerleave', onLeave);
      card.classList.add('tilt-on');
    });
  })();

  /* ---------------------------------------------------------------------
     4) Back-to-top button with a scroll-progress ring
     --------------------------------------------------------------------- */
  (function scrollRing() {
    var btn = document.getElementById('back-to-top');
    if (!btn) return;
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'btt-ring');
    svg.setAttribute('viewBox', '0 0 48 48');
    var track = document.createElementNS(NS, 'circle');
    var prog = document.createElementNS(NS, 'circle');
    [track, prog].forEach(function (c) {
      c.setAttribute('cx', '24'); c.setAttribute('cy', '24'); c.setAttribute('r', '21');
      c.setAttribute('fill', 'none');
    });
    track.setAttribute('class', 'btt-track');
    prog.setAttribute('class', 'btt-prog');
    var C = 2 * Math.PI * 21;
    prog.style.strokeDasharray = C;
    prog.style.strokeDashoffset = C;
    svg.appendChild(track); svg.appendChild(prog);
    btn.appendChild(svg);

    var ticking = false;
    function update() {
      var st = window.scrollY || document.documentElement.scrollTop;
      var h = document.documentElement.scrollHeight - window.innerHeight;
      var p = h > 0 ? clamp(st / h, 0, 1) : 0;
      prog.style.strokeDashoffset = C * (1 - p);
      ticking = false;
    }
    window.addEventListener('scroll', function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    update();
  })();

  /* ---------------------------------------------------------------------
     5) TOC click — scroll so the heading lands BELOW the fixed top bar
        (overrides tocbot's offset, which assumed a shorter bar)
     --------------------------------------------------------------------- */
  (function tocScroll() {
    var OFFSET = 96; // 76px bar + breathing room
    document.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('#toc a[href^="#"]');
      if (!a) return;
      var id = decodeURIComponent(a.getAttribute('href').slice(1));
      var el = id && document.getElementById(id);
      if (!el) return;
      e.preventDefault();
      e.stopPropagation(); // beat tocbot's own handler
      var y = el.getBoundingClientRect().top + window.scrollY - OFFSET;
      window.scrollTo({ top: y, behavior: reduce ? 'auto' : 'smooth' });
      if (history.replaceState) history.replaceState(null, '', '#' + id);
    }, true); // capture phase
  })();

  /* ---------------------------------------------------------------------
     6) Minimal search — collapsed magnifier expands into a dark overlay
     --------------------------------------------------------------------- */
  (function searchOverlay() {
    var mq = window.matchMedia('(min-width: 1200px)');
    var search = document.getElementById('search');
    var overlay = document.getElementById('search-overlay');
    var input = document.getElementById('search-input');
    var cancel = document.getElementById('search-cancel');
    if (!search || !overlay) return;

    function open() {
      if (!mq.matches) return;
      document.body.classList.add('search-open');
      if (input) setTimeout(function () { input.focus(); }, 80);
    }
    function close() {
      document.body.classList.remove('search-open');
      // reset Chirpy's search state (clears results + restores the main content
      // it hides while searching) so closing never leaves the page shifted
      if (input) input.value = '';
      if (cancel) cancel.click();
      if (input) input.blur();
    }

    search.addEventListener('click', function (e) {
      if (!mq.matches) return;
      if (!document.body.classList.contains('search-open')) {
        e.preventDefault();
        open();
      }
    });
    overlay.addEventListener('click', close);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && document.body.classList.contains('search-open')) close();
      // quick-open with "/"
      if (e.key === '/' && !document.body.classList.contains('search-open') &&
          mq.matches && !/^(INPUT|TEXTAREA)$/.test((e.target.tagName || ''))) {
        e.preventDefault();
        open();
      }
    });
  })();
})();
