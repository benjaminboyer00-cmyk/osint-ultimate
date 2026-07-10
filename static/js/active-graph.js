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
    if (d.active) {
      bar.classList.add('active');
      if (label) label.textContent = `Graphe actif : « ${d.active.name} » — vos recherches s'y ajoutent.`;
      if (clearBtn) clearBtn.style.display = 'inline-block';
      if (openLink) { openLink.style.display = 'inline-block'; openLink.href = '/graph?entity_id=' + d.active.root_id; }
    } else {
      bar.classList.remove('active');
      if (label) label.textContent = 'Aucun graphe actif — chaque recherche crée un graphe isolé.';
      if (clearBtn) clearBtn.style.display = 'none';
      if (openLink) openLink.style.display = 'none';
    }
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
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadActiveGraph);
  else loadActiveGraph();
})();
