(function () {
  const protocol = location.protocol === 'https:' ? 'https:' : 'http:';
  const wsProtocol = protocol === 'https:' ? 'wss:' : 'ws:';
  const host = location.hostname;
  const frontendPort = location.port;

  // nginx proxies /api/, /auth/, and /ws to the backend container internally.
  // Always use the same origin so all requests go through nginx on port 8090.
  const backendOrigin = location.origin;

  window._HD_API = backendOrigin;
  window._HD_WS = `${wsProtocol}//${new URL(backendOrigin).host}/ws`;
})();
