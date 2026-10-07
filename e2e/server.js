#!/usr/bin/env node
/**
 * e2e/server.js
 *
 * Tiny static-file server that serves the e2e/ directory over http://localhost:8080.
 * WebAuthn requires a Secure Context (HTTPS or localhost), so localhost:8080 works.
 *
 * Usage:
 *   node e2e/server.js          # serves e2e/ at http://localhost:8080/
 *   PORT=3000 node e2e/server.js
 *
 * No dependencies beyond Node.js built-ins.
 */

'use strict';

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT    = parseInt(process.env.PORT || '8080', 10);
const WEBROOT = path.resolve(__dirname); // e2e/ directory

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js'  : 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css' : 'text/css; charset=utf-8',
  '.txt' : 'text/plain; charset=utf-8',
  '.md'  : 'text/markdown; charset=utf-8',
};

const server = http.createServer((req, res) => {
  // Normalise the URL path and resolve to a filesystem path.
  let urlPath = req.url.split('?')[0]; // strip query string
  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';

  const filePath = path.join(WEBROOT, path.normalize(urlPath));

  // Security: prevent path-traversal outside WEBROOT.
  if (!filePath.startsWith(WEBROOT + path.sep) && filePath !== WEBROOT) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end(`404 Not Found: ${urlPath}`);
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`500 Internal Server Error: ${err.message}`);
      }
      return;
    }

    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type' : mime,
      'Content-Length': data.length,
      // Allow SharedArrayBuffer if ever needed; harmless for our use.
      'Cross-Origin-Opener-Policy' : 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(data);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Serving e2e/ at http://localhost:${PORT}/`);
  console.log('Open http://localhost:8080/ in your browser to register a credential.');
  console.log('Press Ctrl+C to stop.');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Set PORT=<other> to use a different port.`);
  } else {
    console.error('Server error:', err);
  }
  process.exit(1);
});
