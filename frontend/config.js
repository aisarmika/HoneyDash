/**
 * HoneyDash API endpoint auto-configuration
 *
 * Local dev  (http://localhost:8090/…):
 *   Frontend is served by the nginx container on :8090
 *   Backend runs on :8000 — call it directly.
 *
 * Production (https://yourdomain.com/…):
 *   nginx reverse-proxy routes /api/, /auth/, /ws to the backend
 *   on the same domain — no port in the URL needed.
 */
(function () {
  const h     = location.hostname;
  const local = h === 'localhost' || h === '127.0.0.1';

  window._HD_API = local
    ? 'http://localhost:8000'
    : location.origin;

  window._HD_WS = local
    ? 'ws://localhost:8000/ws'
    : (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
})();
