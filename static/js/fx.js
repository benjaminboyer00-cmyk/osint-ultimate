/* ============================================================
   OSINT Ultimate — effets visuels modernes (léger, sans dépendance)
   - Fond « réseau » animé (nœuds + liens qui dérivent) : évoque un
     graphe d'entités. Réagit au curseur. Coupé si prefers-reduced-motion.
   - Reveal au scroll (IntersectionObserver).
   Optimisé : DPR borné, nœuds plafonnés, pause si onglet caché.
   ============================================================ */
(function () {
  'use strict';
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function initNetwork(canvas) {
    if (!canvas || reduced) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    let W = 0, H = 0, nodes = [], raf = null, running = true;
    const mouse = { x: -9999, y: -9999 };

    function resize() {
      W = canvas.clientWidth; H = canvas.clientHeight;
      canvas.width = W * DPR; canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      const target = Math.min(Math.floor((W * H) / 16000), 84);
      nodes = [];
      for (let i = 0; i < target; i++) {
        nodes.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.35, vy: (Math.random() - 0.5) * 0.35,
        });
      }
    }

    const LINK = 132;      // distance de liaison
    function frame() {
      if (!running) return;
      ctx.clearRect(0, 0, W, H);
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
        // légère attraction vers le curseur (micro-interaction)
        const dxm = mouse.x - n.x, dym = mouse.y - n.y;
        const dm = Math.hypot(dxm, dym);
        if (dm < 160) { n.x += dxm * 0.0016; n.y += dym * 0.0016; }
      }
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < LINK) {
            const o = (1 - d / LINK) * 0.5;
            ctx.strokeStyle = `rgba(77,159,255,${o})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      for (const n of nodes) {
        const near = Math.hypot(mouse.x - n.x, mouse.y - n.y) < 160;
        ctx.fillStyle = near ? 'rgba(0,229,160,.95)' : 'rgba(0,229,160,.55)';
        ctx.beginPath(); ctx.arc(n.x, n.y, near ? 2.4 : 1.6, 0, Math.PI * 2); ctx.fill();
      }
      raf = requestAnimationFrame(frame);
    }

    function start() { if (!running) { running = true; frame(); } }
    function stop() { running = false; if (raf) cancelAnimationFrame(raf); }

    window.addEventListener('resize', resize, { passive: true });
    window.addEventListener('pointermove', e => {
      const r = canvas.getBoundingClientRect(); mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top;
    }, { passive: true });
    window.addEventListener('pointerleave', () => { mouse.x = mouse.y = -9999; });
    document.addEventListener('visibilitychange', () => document.hidden ? stop() : start());

    resize(); running = true; frame();
  }

  function initReveal() {
    const els = document.querySelectorAll('.reveal');
    if (!els.length) return;
    if (reduced || !('IntersectionObserver' in window)) {
      els.forEach(el => el.classList.add('in')); return;
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { threshold: 0.12 });
    els.forEach(el => io.observe(el));
  }

  function boot() {
    document.querySelectorAll('canvas[data-network]').forEach(initNetwork);
    initReveal();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
