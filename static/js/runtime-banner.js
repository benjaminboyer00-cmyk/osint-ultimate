/**
 * Bannière informative (Hugging Face / mode dégradé) via GET /api/runtime.
 */
(function (global) {
  const BANNER_ID = 'osint-runtime-banner';

  function injectStyles() {
    if (document.getElementById('osint-runtime-banner-style')) return;
    const s = document.createElement('style');
    s.id = 'osint-runtime-banner-style';
    s.textContent = `
      #${BANNER_ID}{
        position:sticky;top:0;z-index:9999;
        display:flex;align-items:flex-start;gap:.75rem;
        padding:.55rem 1rem;font-size:.78rem;line-height:1.45;
        background:rgba(255,160,50,.12);border-bottom:1px solid rgba(255,160,50,.35);
        color:#ffb347;font-family:Inter,system-ui,sans-serif;
      }
      #${BANNER_ID} button{
        margin-left:auto;flex-shrink:0;border:none;background:transparent;
        color:inherit;cursor:pointer;font-size:1.1rem;padding:0 .25rem;
      }
      #${BANNER_ID} a{color:#4d9fff}
    `;
    document.head.appendChild(s);
  }

  function showBanner(text, link) {
    if (document.getElementById(BANNER_ID)) return;
    injectStyles();
    const el = document.createElement('div');
    el.id = BANNER_ID;
    el.setAttribute('role', 'status');
    let html = `<span>${text}</span>`;
    if (link) {
      html += ` <a href="${link}" target="_blank" rel="noopener">VPS / doc</a>`;
    }
    html += '<button type="button" aria-label="Fermer">×</button>';
    el.innerHTML = html;
    el.querySelector('button').onclick = () => {
      el.remove();
      try { sessionStorage.setItem('osint_runtime_banner_dismissed', '1'); } catch (_) {}
    };
    document.body.prepend(el);
  }

  async function initRuntimeBanner() {
    try {
      if (sessionStorage.getItem('osint_runtime_banner_dismissed')) return;
    } catch (_) {}
    try {
      const r = await fetch('/api/runtime', { credentials: 'same-origin' });
      if (!r.ok) return;
      const d = await r.json();
      if (!d.hf_space && !d.hint) return;
      const msg = d.hint || (
        'Mode démo : certains modules (médias sociaux complets, file Celery) nécessitent le VPS.'
      );
      showBanner(msg, null);
    } catch (_) {}
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initRuntimeBanner);
  } else {
    initRuntimeBanner();
  }

  global.osintInitRuntimeBanner = initRuntimeBanner;
})(typeof window !== 'undefined' ? window : globalThis);
