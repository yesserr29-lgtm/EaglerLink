'use strict';

/**
 * =========================================================
 *  Eagler WSS Reverse Proxy + Static Site (Template)
 * =========================================================
 *  - Serves files from /public
 *  - Proxies WebSocket upgrades to UPSTREAM_WSS
 *  - Works even when WS path is "/" (no /wss needed)
 *
 *  Setup:
 *   1) Put your website files in /public
 *   2) Set UPSTREAM_WSS below to your eagler host URL
 *   3) (Optional) Set WS_SECRET_PATH to lock access
 * =========================================================
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

/* =======================
   CONFIG (EDIT THESE)
   ======================= */
const PORT = process.env.PORT || 10000;

// Your EaglerHost server WSS URL:
const UPSTREAM_WSS = process.env.UPSTREAM_WSS || 'wss://steak.eagler.host/';

// Static site folder:
const PUBLIC_DIR = path.join(__dirname, 'public');

// OPTIONAL: lock the WS proxy behind a secret path.
// Example: "/secret123" -> client connects to wss://yourdomain.com/secret123
// Set to "" to allow any path.
const WS_SECRET_PATH = process.env.WS_SECRET_PATH || ''; // e.g. "/secret123" or ""

/* =======================
   INTERNALS
   ======================= */
function log(...a) {
  console.log(new Date().toISOString(), ...a);
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return ({
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8',
  })[ext] || 'application/octet-stream';
}

function serveStatic(req, res) {
  const urlPathRaw = (req.url || '').split('?')[0];

  if (urlPathRaw === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('ok\n');
    return;
  }

  let urlPath = urlPathRaw;
  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';

  let safePath;
  try {
    safePath = path.normalize(decodeURIComponent(urlPath)).replace(/^(\.\.(\/|\\|$))+/, '');
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Bad Request');
    return;
  }

  const filePath = path.join(PUBLIC_DIR, safePath);

  // Prevent directory escape
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, st) => {
    const chosen = (!err && st.isFile())
      ? filePath
      : path.join(PUBLIC_DIR, 'index.html');

    fs.readFile(chosen, (e2, data) => {
      if (e2) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
      }

      res.writeHead(200, {
        'content-type': contentType(chosen),
        'cache-control': chosen.endsWith('.html') ? 'no-cache' : 'public, max-age=86400',
      });
      res.end(data);
    });
  });
}

const server = http.createServer(serveStatic);

// noServer WS server so "/" can stay HTTP too
const wss = new WebSocket.Server({
  noServer: true,
  perMessageDeflate: false,
  maxPayload: 0,
});

server.on('upgrade', (req, socket, head) => {
  const upgrade = (req.headers.upgrade || '').toLowerCase();
  if (upgrade !== 'websocket') return socket.destroy();

  const pathOnly = (req.url || '').split('?')[0];

  // If locked, require exact secret path
  if (WS_SECRET_PATH && pathOnly !== WS_SECRET_PATH) {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (client, req) => {
  const ip =
    (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown';

  const pathOnly = (req.url || '').split('?')[0];

  const protoHeader = req.headers['sec-websocket-protocol'];
  const protocols = protoHeader
    ? protoHeader.split(',').map(s => s.trim()).filter(Boolean)
    : undefined;

  log('[IN ] ws connect', { ip, path: pathOnly, protocols });

  // Queue early packets until upstream opens (helps server list MOTD/ping)
  const MAX_QUEUE_BYTES = 2 * 1024 * 1024;
  const queue = [];
  let queueBytes = 0;

  const upstream = new WebSocket(UPSTREAM_WSS, protocols, {
    perMessageDeflate: false,
    handshakeTimeout: 15000,
  });

  const kill = (why) => {
    try { client.terminate(); } catch {}
    try { upstream.terminate(); } catch {}
    log('[CLS]', { ip, why });
  };

  function enqueue(data, isBinary) {
    const size = typeof data === 'string' ? Buffer.byteLength(data) : (data?.length ?? 0);
    queue.push({ data, isBinary, size });
    queueBytes += size;
    if (queueBytes > MAX_QUEUE_BYTES) kill('queue overflow');
  }

  // Client -> Upstream
  client.on('message', (data, isBinary) => {
    if (upstream.readyState === WebSocket.OPEN) {
      upstream.send(data, { binary: isBinary, compress: false });
    } else if (upstream.readyState === WebSocket.CONNECTING) {
      enqueue(data, isBinary);
    } else {
      kill('upstream not available');
    }
  });

  upstream.on('open', () => {
    log('[UP ] open', { ip });

    while (queue.length && upstream.readyState === WebSocket.OPEN) {
      const m = queue.shift();
      queueBytes -= m.size;
      upstream.send(m.data, { binary: m.isBinary, compress: false });
    }
  });

  // Upstream -> Client
  upstream.on('message', (data, isBinary) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data, { binary: isBinary, compress: false });
    }
  });

  upstream.on('close', (code, reason) => {
    log('[UP ] close', { ip, code, reason: reason?.toString?.() || '' });
    kill('upstream closed');
  });

  client.on('close', (code, reason) => {
    log('[IN ] close', { ip, code, reason: reason?.toString?.() || '' });
    kill('client closed');
  });

  upstream.on('error', (err) => {
    log('[UP ] error', { ip, err: err?.message || String(err) });
    kill('upstream error');
  });

  client.on('error', (err) => {
    log('[IN ] error', { ip, err: err?.message || String(err) });
    kill('client error');
  });
});

server.listen(PORT, '0.0.0.0', () => {
  log(`listening on ${PORT} (HTTP: /public, WSS: ${WS_SECRET_PATH || 'ANY PATH'})`);
});
