/**
 * Socket.IO — désactivé sur Hugging Face (400 polling côté proxy HF).
 * Polling HTTP /scan/<id>?poll_token=… à la place.
 */
(function (global) {
  function isHuggingFaceHost() {
    const h = (global.location && global.location.hostname) || '';
    return h.includes('hf.space') || h.includes('huggingface.co');
  }

  function createOsintSocket() {
    if (isHuggingFaceHost()) {
      return null;
    }
    if (typeof global.io !== 'function') {
      return null;
    }
    return global.io({
      transports: ['polling', 'websocket'],
      upgrade: true,
      withCredentials: true,
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 2000,
      timeout: 20000,
    });
  }

  global.createOsintSocket = createOsintSocket;
  global.osintIsHuggingFace = isHuggingFaceHost;
})(typeof window !== 'undefined' ? window : globalThis);
