(function () {
  const protocol = location.protocol === 'https:' ? 'https:' : 'http:';
  const wsProtocol = protocol === 'https:' ? 'wss:' : 'ws:';
  const host = location.hostname;
  const frontendPort = location.port;

  // Docker Compose exposes the static frontend on :8090 and FastAPI on :8000.
  // If a reverse proxy serves everything on one origin, use the same origin.
  const backendOrigin = frontendPort === '8090'
    ? `${protocol}//${host}:8000`
    : location.origin;

  window._HD_API = backendOrigin;
  window._HD_WS = `${wsProtocol}//${new URL(backendOrigin).host}/ws`;
})();
