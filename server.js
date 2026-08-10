// PrivateMesh relay: forwards encrypted blobs between two registered
// clients. Never sees plaintext. Queues briefly for offline recipients,
// then drops. No database, no logs of message content.

const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const ID_RE = /^[0-9a-f]{64}$/i; // sha-256 hex of a contact's public key
const MAX_QUEUE_PER_ID = 200;
const QUEUE_TTL_MS = 48 * 60 * 60 * 1000; // 48h
const MAX_CIPHERTEXT_B64_LEN = 20000; // generous cap for a text message
const RATE_LIMIT_MSGS = 20;
const RATE_LIMIT_WINDOW_MS = 10 * 1000;

const clients = new Map(); // id -> ws
const queues = new Map(); // id -> [{ envelope, expiresAt }]

const wss = new WebSocket.Server({ port: PORT });

function safeSend(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function enqueue(id, envelope) {
  let q = queues.get(id);
  if (!q) {
    q = [];
    queues.set(id, q);
  }
  if (q.length >= MAX_QUEUE_PER_ID) q.shift();
  q.push({ envelope, expiresAt: Date.now() + QUEUE_TTL_MS });
}

function flushQueue(id, ws) {
  const q = queues.get(id);
  if (!q || q.length === 0) return;
  const now = Date.now();
  for (const item of q) {
    if (item.expiresAt > now) safeSend(ws, { type: 'message', ...item.envelope });
  }
  queues.delete(id);
}

// Periodic sweep of expired queued messages.
setInterval(() => {
  const now = Date.now();
  for (const [id, q] of queues) {
    const filtered = q.filter((i) => i.expiresAt > now);
    if (filtered.length === 0) queues.delete(id);
    else queues.set(id, filtered);
  }
}, 10 * 60 * 1000);

wss.on('connection', (ws) => {
  let myId = null;
  let rateCount = 0;
  let rateWindowStart = Date.now();
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!msg || typeof msg.type !== 'string') return;

    const now = Date.now();
    if (now - rateWindowStart > RATE_LIMIT_WINDOW_MS) {
      rateWindowStart = now;
      rateCount = 0;
    }
    rateCount += 1;
    if (rateCount > RATE_LIMIT_MSGS) return;

    if (msg.type === 'register') {
      if (typeof msg.id !== 'string' || !ID_RE.test(msg.id)) {
        safeSend(ws, { type: 'error', reason: 'bad_id' });
        ws.close();
        return;
      }
      myId = msg.id;
      clients.set(myId, ws);
      flushQueue(myId, ws);
      return;
    }

    if (msg.type === 'send') {
      if (!myId) {
        safeSend(ws, { type: 'error', reason: 'not_registered' });
        return;
      }
      if (typeof msg.to !== 'string' || !ID_RE.test(msg.to)) return;
      if (typeof msg.ciphertext !== 'string' || msg.ciphertext.length > MAX_CIPHERTEXT_B64_LEN) return;

      const envelope = { from: myId, ciphertext: msg.ciphertext, ts: Date.now() };
      const target = clients.get(msg.to);
      if (target && target.readyState === WebSocket.OPEN) {
        safeSend(target, { type: 'message', ...envelope });
      } else {
        enqueue(msg.to, envelope);
      }
    }
  });

  ws.on('close', () => {
    if (myId && clients.get(myId) === ws) clients.delete(myId);
  });
});

// Drop dead connections (no pong within one interval).
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30 * 1000);

wss.on('close', () => clearInterval(heartbeat));

console.log(`PrivateMesh relay listening on port ${PORT}`);
