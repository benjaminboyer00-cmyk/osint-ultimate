/** En-tête CSRF pour fetch JSON (si meta csrf-token présente). */
(function () {
  function csrfHeaders(extra) {
    const h = Object.assign({}, extra || {});
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) h['X-CSRFToken'] = meta.content;
    return h;
  }
  window.osintFetch = function (url, opts) {
    opts = opts || {};
    opts.credentials = opts.credentials || 'same-origin';
    opts.headers = csrfHeaders(opts.headers);
    return fetch(url, opts);
  };
})();
