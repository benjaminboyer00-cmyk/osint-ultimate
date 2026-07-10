/* Graphe actif — partagé par Express et Expert.
   Crée un graphe nommé ; les recherches suivantes s'y rattachent.
   S'active si la page contient #graph-bar (sinon inerte). */
(function () {
  'use strict';
  function esc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  async function loadActiveGraph(){
    const bar = document.getElementById('graph-bar');
    if (!bar) return;
    let d;
    try { d = await (await fetch('/graph/active')).json(); } catch (e) { return; }
    const sel = document.getElementById('graph-bar-select');
    const label = document.getElementById('graph-bar-label');
    const clearBtn = document.getElementById('graph-bar-clear');
    const openLink = document.getElementById('graph-bar-open');
    const graphs = d.graphs || [];
    if (sel) {
      sel.innerHTML = '<option value="">— Mes graphes —</option>' + graphs.map(g =>
        `<option value="${g.root_id}" ${g.active ? 'selected' : ''}>${esc((g.name || '').slice(0,40))}</option>`
      ).join('');
      sel.style.display = graphs.length ? 'inline-block' : 'none';
    }
    const analyzeBtn = document.getElementById('graph-bar-analyze');
    if (d.active) {
      bar.classList.add('active');
      if (label) label.textContent = `Graphe actif : « ${d.active.name} » — vos recherches s'y ajoutent.`;
      if (clearBtn) clearBtn.style.display = 'inline-block';
      if (openLink) { openLink.style.display = 'inline-block'; openLink.href = '/graph?entity_id=' + d.active.root_id; }
      if (analyzeBtn) { analyzeBtn.style.display = 'inline-block'; analyzeBtn.dataset.root = d.active.root_id; }
    } else {
      bar.classList.remove('active');
      if (label) label.textContent = 'Aucun graphe actif — chaque recherche crée un graphe isolé.';
      if (clearBtn) clearBtn.style.display = 'none';
      if (openLink) openLink.style.display = 'none';
      if (analyzeBtn) analyzeBtn.style.display = 'none';
    }
  }

  // Analyse IA du graphe actif dans un modal (réutilise /graph/entity/<id>/analysis)
  async function analyzeActiveGraph(){
    const btn = document.getElementById('graph-bar-analyze');
    const root = btn && btn.dataset.root;
    if (!root) { alert('Aucun graphe actif à analyser.'); return; }
    const modal = ensureModal();
    modal.body.innerHTML = '<p style="color:var(--muted)">🧠 Analyse du graphe en cours…</p>';
    modal.overlay.style.display = 'flex';
    let d;
    try { d = await (await fetch('/graph/entity/' + root + '/analysis')).json(); }
    catch (e) { modal.body.innerHTML = '<p style="color:var(--danger)">Analyse indisponible.</p>'; return; }
    if (d.error) { modal.body.innerHTML = `<p style="color:var(--muted)">${esc(d.error)}</p>`; return; }
    let h = '';
    if (d.synthese) h += `<p style="line-height:1.55;margin:.2rem 0 .8rem">${esc(d.synthese)}</p>`;
    if (d.incoherences && d.incoherences.length) {
      h += '<h4 style="color:#ffb454;font-size:.8rem;margin:.6rem 0 .3rem">⚠️ Incohérences</h4><ul style="padding-left:1.1rem;font-size:.86rem">';
      d.incoherences.forEach(i => h += `<li>${esc(i.observation)}</li>`); h += '</ul>';
    }
    if (d.pistes && d.pistes.length) {
      h += '<h4 style="color:var(--accent);font-size:.8rem;margin:.6rem 0 .3rem">🎯 Pistes</h4><ol style="padding-left:1.2rem;font-size:.86rem">';
      [...d.pistes].sort((a,b)=>(a.priorite||9)-(b.priorite||9)).forEach(p =>
        h += `<li><b>${esc(p.action)}</b> <span style="color:var(--muted)">— ${esc(p.raison||'')}</span></li>`); h += '</ol>';
    }
    h += `<a href="/graph?entity_id=${encodeURIComponent(root)}" class="gb-btn gb-primary" style="margin-top:.8rem">Ouvrir le graphe complet →</a>`;
    modal.body.innerHTML = h || '<p style="color:var(--muted)">Pas encore assez de données pour une analyse.</p>';
  }

  let _modal = null;
  function ensureModal(){
    if (_modal) return _modal;
    const overlay = document.createElement('div');
    overlay.style.cssText = 'display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);align-items:center;justify-content:center;padding:1rem';
    const box = document.createElement('div');
    box.className = 'ds-card ds-card-glass';
    box.style.cssText = 'max-width:560px;width:100%;max-height:82vh;overflow:auto;position:relative';
    const close = document.createElement('button');
    close.textContent = '✕'; close.setAttribute('aria-label','Fermer');
    close.style.cssText = 'position:absolute;top:.7rem;right:.9rem;background:none;border:none;color:var(--muted);font-size:1.1rem;cursor:pointer';
    close.onclick = () => overlay.style.display = 'none';
    const title = document.createElement('h3');
    title.textContent = '🧠 Analyse IA du graphe'; title.style.cssText = 'font-size:1rem;margin-bottom:.6rem';
    const body = document.createElement('div');
    box.append(close, title, body); overlay.appendChild(box);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.style.display = 'none'; });
    document.body.appendChild(overlay);
    _modal = { overlay, body }; return _modal;
  }
  async function createGraph(){
    const name = prompt('Nom du graphe / de l\'enquête :', 'Enquête ' + new Date().toLocaleDateString('fr-FR'));
    if (!name) return;
    const r = await fetch('/graph/create', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name }) });
    if (!r.ok) { alert('Création impossible'); return; }
    await loadActiveGraph();
  }
  async function activateGraph(rootId){
    if (!rootId) return;
    await fetch('/graph/set-active', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ root_id: parseInt(rootId, 10) }) });
    await loadActiveGraph();
  }
  async function clearActiveGraph(){
    await fetch('/graph/clear-active', { method:'POST' });
    await loadActiveGraph();
  }
  // exposé global (appelé par les onclick des templates)
  window.loadActiveGraph = loadActiveGraph;
  window.createGraph = createGraph;
  window.activateGraph = activateGraph;
  window.clearActiveGraph = clearActiveGraph;
  window.analyzeActiveGraph = analyzeActiveGraph;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadActiveGraph);
  else loadActiveGraph();
})();
