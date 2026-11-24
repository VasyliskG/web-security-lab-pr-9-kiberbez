'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const HOST = '127.0.0.1';
const PORT = 3000;
const MAX_BODY_BYTES = 4 * 1024;
const MAX_MESSAGES = 100;
const SESSION_TTL_MS = 30 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 5;
const ALLOWED_ORIGIN = `http://${HOST}:${PORT}`;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DOWNLOAD_DIR = path.join(PUBLIC_DIR, 'downloads');

const sessions = new Map();
const messages = [];
const rateLimits = new Map();
const allowedDownloads = new Map([
  ['guide.txt', path.join(DOWNLOAD_DIR, 'guide.txt')],
]);

function setSecurityHeaders(response) {
  response.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'",
  );
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function send(response, statusCode, body, contentType = 'application/json; charset=utf-8') {
  setSecurityHeaders(response);
  response.statusCode = statusCode;
  response.setHeader('Content-Type', contentType);
  response.end(contentType.startsWith('application/json') ? JSON.stringify(body) : body);
}

function sendError(response, statusCode, message) {
  send(response, statusCode, { error: message });
}

function parseCookies(request) {
  const cookies = {};
  const header = request.headers.cookie;
  if (!header) return cookies;

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    cookies[name] = value;
  }
  return cookies;
}

function getSession(request, response) {
  const sid = parseCookies(request).sid;
  const session = sid ? sessions.get(sid) : undefined;
  if (!session || Date.now() - session.createdAt >= SESSION_TTL_MS) {
    if (sid) sessions.delete(sid);
    const newSid = crypto.randomBytes(32).toString('hex');
    const newSession = {
      createdAt: Date.now(),
      csrfToken: crypto.randomBytes(32).toString('hex'),
    };
    sessions.set(newSid, newSession);
    response.setHeader(
      'Set-Cookie',
      `sid=${newSid}; Max-Age=${SESSION_TTL_MS / 1000}; HttpOnly; SameSite=Strict; Path=/`,
    );
    return newSession;
  }

  response.setHeader(
    'Set-Cookie',
    `sid=${sid}; Max-Age=${SESSION_TTL_MS / 1000}; HttpOnly; SameSite=Strict; Path=/`,
  );
  return session;
}

function readJsonBody(request, response) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bodyBytes = 0;
    let tooLarge = false;

    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      bodyBytes += Buffer.byteLength(chunk, 'utf8');
      if (bodyBytes > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      body += chunk;
    });
    request.on('end', () => {
      if (tooLarge) {
        sendError(response, 413, 'Request body is too large');
        reject(new Error('request body too large'));
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('invalid JSON'));
      }
    });
    request.on('error', reject);
  });
}

function validateMessage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return 'Request body must be an object';
  }

  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('name') || !keys.includes('message')) {
    return 'Only name and message fields are allowed';
  }
  if (typeof value.name !== 'string' || typeof value.message !== 'string') {
    return 'Name and message must be strings';
  }

  const name = value.name.trim();
  const message = value.message.trim();
  if (name.length < 2 || name.length > 40) {
    return 'Name must contain 2 to 40 characters';
  }
  if (message.length < 5 || message.length > 500) {
    return 'Message must contain 5 to 500 characters';
  }
  return null;
}

function isRateLimited(request) {
  const source = request.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = rateLimits.get(source);
  if (!entry || now - entry.startedAt >= RATE_WINDOW_MS) {
    rateLimits.set(source, { startedAt: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT;
}

function checkCsrf(request, response) {
  const origin = request.headers.origin;
  if (origin !== ALLOWED_ORIGIN) {
    sendError(response, 403, 'Forbidden');
    return null;
  }

  const sid = parseCookies(request).sid;
  const session = sid ? sessions.get(sid) : undefined;
  if (!session || Date.now() - session.createdAt >= SESSION_TTL_MS) {
    sendError(response, 403, 'Forbidden');
    return null;
  }
  if (request.headers['x-csrf-token'] !== session.csrfToken) {
    sendError(response, 403, 'Forbidden');
    return null;
  }
  return session;
}

function serveStatic(response, filePath, contentType) {
  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendError(response, 404, 'Not found');
      return;
    }
    send(response, 200, content, contentType);
  });
}

function handleRequest(request, response) {
  const url = new URL(request.url, ALLOWED_ORIGIN);

  if (request.method === 'GET' && url.pathname === '/') {
    serveStatic(response, path.join(PUBLIC_DIR, 'index.html'), 'text/html; charset=utf-8');
    return;
  }
  if (request.method === 'GET' && url.pathname === '/app.js') {
    serveStatic(response, path.join(PUBLIC_DIR, 'app.js'), 'text/javascript; charset=utf-8');
    return;
  }
  if (request.method === 'GET' && url.pathname === '/styles.css') {
    serveStatic(response, path.join(PUBLIC_DIR, 'styles.css'), 'text/css; charset=utf-8');
    return;
  }
  if (request.method === 'GET' && url.pathname === '/health') {
    send(response, 200, { status: 'ok' });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/session') {
    const session = getSession(request, response);
    send(response, 200, { csrfToken: session.csrfToken });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/messages') {
    send(response, 200, { messages });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/api/messages') {
    if (isRateLimited(request)) {
      sendError(response, 429, 'Too many requests');
      return;
    }
    if (!checkCsrf(request, response)) return;
    if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
      sendError(response, 400, 'Content-Type must be application/json');
      return;
    }

    readJsonBody(request, response)
      .then((body) => {
        const validationError = validateMessage(body);
        if (validationError) {
          sendError(response, 400, validationError);
          return;
        }
        const message = {
          name: body.name.trim(),
          message: body.message.trim(),
          createdAt: new Date().toISOString(),
        };
        messages.push(message);
        if (messages.length > MAX_MESSAGES) messages.shift();
        send(response, 201, { message });
      })
      .catch((error) => {
        if (error.message !== 'request body too large') {
          sendError(response, 400, 'Invalid JSON body');
        }
      });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/api/download') {
    const fileName = url.searchParams.get('file');
    const filePath = allowedDownloads.get(fileName);
    if (!filePath) {
      sendError(response, 404, 'Not found');
      return;
    }
    serveStatic(response, filePath, 'text/plain; charset=utf-8');
    return;
  }

  sendError(response, 404, 'Not found');
}

const server = http.createServer((request, response) => {
  try {
    handleRequest(request, response);
  } catch (error) {
    console.error('Request handling error:', error);
    if (!response.headersSent) sendError(response, 500, 'Internal server error');
    else response.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Server listening at ${ALLOWED_ORIGIN}`);
});
