/**
 * Polling unifié GET /scan/<id>?poll_token=… (Hugging Face, fallback Socket.IO).
 */
(function (global) {
  function pollUrl(scanId, pollToken) {
    const qs = pollToken ? `?poll_token=${encodeURIComponent(pollToken)}` : '';
    return `/scan/${scanId}${qs}`;
  }

  function isScanDone(data) {
    if (!data || typeof data !== 'object') return false;
    if (data.error && !data.status) return true;
    const st = data.status || (data._meta && data._meta.status);
    if (st === 'completed' || st === 'failed') return true;
    if (st === 'pending' || st === 'running') return false;
    if (data.Profil && (data.Followers != null || data.Bio || data['Nom complet'] || data.Description)) {
      return true;
    }
    if (data.highlights || data.Résultat || data['Sites trouvés'] || data['Fuites'] || data.Emails) {
      return true;
    }
    const keys = Object.keys(data).filter((k) => !k.startsWith('_'));
    return keys.length > 2;
  }

  function defaultIntervalMs() {
    if (typeof global.osintIsHuggingFace === 'function' && global.osintIsHuggingFace()) {
      return 2000;
    }
    return 3500;
  }

  /**
   * @param {number} scanId
   * @param {string|null} pollToken
   * @param {object} opts - onDone, onError, on401, onTimeout, isActive, intervalMs, maxMs
   * @returns {function} cancel
   */
  function startPoll(scanId, pollToken, opts) {
    const o = opts || {};
    const intervalMs = o.intervalMs || defaultIntervalMs();
    const maxMs = o.maxMs || 120000;
    let cancelled = false;

    const iv = setInterval(async () => {
      if (cancelled) return;
      if (typeof o.isActive === 'function' && !o.isActive(scanId)) {
        clearInterval(iv);
        return;
      }
      try {
        const r = await fetch(pollUrl(scanId, pollToken), { credentials: 'include' });
        if (r.status === 401) {
          clearInterval(iv);
          if (o.on401) o.on401();
          else if (o.onError) o.onError('Session expirée — reconnectez-vous.');
          return;
        }
        const d = await r.json();
        if (!isScanDone(d)) return;
        clearInterval(iv);
        if (typeof o.isActive === 'function' && !o.isActive(scanId)) return;
        if (d.error && d.status === 'failed') {
          if (o.onError) o.onError(d.error);
        } else if (o.onDone) {
          o.onDone(d);
        }
      } catch (e) {
        /* réseau transitoire — on réessaie */
      }
    }, intervalMs);

    const to = setTimeout(() => {
      clearInterval(iv);
      if (!cancelled && o.onTimeout) o.onTimeout();
    }, maxMs);

    return function cancel() {
      cancelled = true;
      clearInterval(iv);
      clearTimeout(to);
    };
  }

  global.OsintScanPoll = {
    pollUrl: pollUrl,
    isScanDone: isScanDone,
    startPoll: startPoll,
    defaultIntervalMs: defaultIntervalMs,
  };
})(typeof window !== 'undefined' ? window : globalThis);
