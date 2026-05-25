/**
 * Socket.IO — polling prioritaire sur Hugging Face (proxy wss souvent refusé).
 */
(function (global) {
  function isHuggingFaceHost() {
    const h = (global.location && global.location.hostname) || '';
    return h.includes('hf.space') || h.includes('huggingface.co');
  }

  function createOsintSocket() {
    if (typeof global.io !== 'function') {
      return null;
    }
    const onHF = isHuggingFaceHost();
    return global.io({
      transports: onHF ? ['polling'] : ['polling', 'websocket'],
      upgrade: !onHF,
      rememberUpgrade: false,
      reconnection: true,
      reconnectionAttempts: 15,
      reconnectionDelay: 2000,
      timeout: 20000,
    });
  }

  global.createOsintSocket = createOsintSocket;
  global.osintIsHuggingFace = isHuggingFaceHost;
})(typeof window !== 'undefined' ? window : globalThis);
