// shit code 

// orospu evladı salak bu kod ne bunu ne hakla uzuna açıyosun modullere bak am k: D
import { setFlagsFromString } from "node:v8";
import { setPriority } from "node:os";
import { setDefaultAutoSelectFamily } from "node:net";
import { connect as TC, createSecureContext as SC } from "node:tls";
import WebSocket from "ws";
import http2, { connect as H2C } from "node:http2";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "node:url";
import crypto from "crypto";

for (const flag of [
  "--max-old-space-size=4096",
  "--max-semi-space-size=256",
  "--expose-gc",
]) {
  try { setFlagsFromString(flag); } catch (e) {}
}

setPriority(0);
setDefaultAutoSelectFamily(true);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CONFIG = {
  wsUrl: "wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json",
  apiHost: "canary.discord.com",
  tokenFile: path.join(__dirname, "list.txt"),
  ourGuildId: "1544902206707335229",
  patchToken: "",
  password: "",
  h2SessionCount: 16,
  tlsSocketCount: 16,
  mfaRefreshInterval: 5 * 60 * 1000,
};

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
const XPROPS = "eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=";

let tokens = [];
let h2Sessions = new Array(CONFIG.h2SessionCount);
let tlsSockets = Array.from({ length: CONFIG.tlsSocketCount }, () => ({ write() {}, destroyed: true }));
let tlsBackoff = new Array(CONFIG.tlsSocketCount).fill(500);
let tlsSession = undefined;
let mfaToken = null;
let requestIdPool = [];
let detectedVanities = new Map();

let _keepAlive = setInterval(() => {}, 2147483647);

const heartbeatBuffer = '{"op":1,"d":null}';

function generateRequestId() {
  if (requestIdPool.length === 0) {
    for (let i = 0; i < 100; i++) requestIdPool.push(crypto.randomBytes(16).toString("hex"));
  }
  return requestIdPool.pop();
}

function loadTokens() {
  if (!fs.existsSync(CONFIG.tokenFile)) {
    console.error(`Token dosyası bulunamadı: ${CONFIG.tokenFile}`);
    return false;
  }
  const content = fs.readFileSync(CONFIG.tokenFile, "utf8");
  tokens = content.split(/\r?\n/).filter(t => t.trim().length > 0);
  return tokens.length > 0;
}

function createH2Session(i) {
  if (h2Sessions[i] && !h2Sessions[i].destroyed) {
    try { h2Sessions[i].destroy(); } catch (e) {}
  }

  const session = H2C(`https://${CONFIG.apiHost}:443`, {
    maxVersion: "TLSv1.3", minVersion: "TLSv1.3",
    ciphers: "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    ecdhCurve: "X25519", ALPNProtocols: ["h2"], rejectUnauthorized: false,
    highWaterMark: 32 * 1024, peerMaxConcurrentStreams: 1000,
    paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
    maxConcurrentStreams: 200, enablePush: false,
    initialWindowSize: 4 * 1024 * 1024, maxFrameSize: 4 * 1024 * 1024,
    headerTableSize: 16384, maxHeaderListSize: 32768,
    secureContext: SC({
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
      ciphers: "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
      ecdhCurve: "X25519", honorCipherOrder: true, rejectUnauthorized: false,
    }),
  });

  session.ref();
  session.on("error", () => {
    try { session.destroy(); } catch (e) {}
  });
  session.once("connect", () => {
    try {
      const req = session.request({ ":method": "GET", ":path": "/api/v9/gateway", ":scheme": "https", ":authority": CONFIG.apiHost });
      req.on("error", () => {});
      req.end();
    } catch (e) {}
  });
  session.on("close", () => {
    setTimeout(() => { h2Sessions[i] = createH2Session(i); }, 100);
  });
  return session;
}

function createTLS(i) {
  if (tlsSockets[i] && !tlsSockets[i].destroyed) {
    try { tlsSockets[i].destroy(); } catch (e) {}
  }

  const s = TC({
    host: CONFIG.apiHost, port: 443, servername: CONFIG.apiHost,
    secureContext: SC({
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
      ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
      sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
      ecdhCurve: "X25519:prime256v1:secp384r1", honorCipherOrder: true, rejectUnauthorized: false,
    }),
    ALPNProtocols: ["http/1.1"], session: tlsSession,
    highWaterMark: 1024 * 1024, handshakeTimeout: 4000, timeout: 30000,
  });

  s.setNoDelay(true);
  s.setKeepAlive(true, 10000);

  s.on("session", (sess) => { tlsSession = sess; });
  s.on("secureConnect", () => {
    tlsSockets[i] = s;
    tlsBackoff[i] = 500;
    try { s.write("\r\n"); } catch (e) {}
  });

  s.on("data", (chunk) => {
    const txt = chunk.toString("latin1");
    // Gateway keepalive yanıtlarını (url: wss://...) cmd ekranına yazmama filtresi
    if (txt.includes('"url":') || txt.includes("gateway.discord.gg")) return;

    const bodyStart = txt.indexOf("\r\n\r\n");
    if (bodyStart === -1) return;
    const body = txt.slice(bodyStart + 4).trim();
    if (body.length > 0) {
      console.log(`[TLS Yanıtı] ${body}`);
    }
  });

  s.on("timeout", () => {
    try { s.destroy(); } catch (e) {}
  });

  s.on("error", () => {
    try { s.destroy(); } catch (e) {}
  });

  s.on("close", () => {
    tlsSockets[i] = { write() {}, destroyed: true };
    setTimeout(() => createTLS(i), tlsBackoff[i]);
    tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 5000);
  });
}

function getMfaToken() {
  return new Promise((resolve) => {
    let resolved = false;
    const safeResolve = (val) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeoutTimer);
        resolve(val);
      }
    };

    const timeoutTimer = setTimeout(() => {
      safeResolve(false);
    }, 5000);

    const sess = h2Sessions.find(s => s && !s.destroyed && !s.closed);
    if (!sess) return safeResolve(false);

    try {
      const req1 = sess.request({
        ":method": "PATCH", ":path": `/api/v9/guilds/${CONFIG.ourGuildId}/vanity-url`,
        ":authority": CONFIG.apiHost, ":scheme": "https",
        "authorization": CONFIG.patchToken, "content-type": "application/json",
        "user-agent": UA, "x-super-properties": XPROPS, "x-request-id": generateRequestId(),
      });

      let r1 = "";
      req1.on("data", c => { r1 += c.toString(); });
      req1.on("error", () => safeResolve(false));
      req1.on("end", () => {
        try {
          const d1 = JSON.parse(r1);
          const ticket = d1 && ((d1.mfa && d1.mfa.ticket) || d1.ticket);
          if (!ticket) return safeResolve(false);

          const bodyMfa = JSON.stringify({ ticket, mfa_type: "password", data: CONFIG.password });
          const req2 = sess.request({
            ":method": "POST", ":path": "/api/v9/mfa/finish",
            ":authority": CONFIG.apiHost, ":scheme": "https",
            "authorization": CONFIG.patchToken, "content-type": "application/json",
            "user-agent": UA, "x-super-properties": XPROPS,
            "content-length": Buffer.byteLength(bodyMfa), "x-request-id": generateRequestId(),
          });

          let r2 = "";
          req2.on("data", c => { r2 += c.toString(); });
          req2.on("error", () => safeResolve(false));
          req2.on("end", () => {
            try {
              const d2 = JSON.parse(r2);
              if (d2 && d2.token) {
                mfaToken = d2.token;
                console.log("[MFA] Token başarıyla güncellendi.");
                safeResolve(true);
              } else {
                safeResolve(false);
              }
            } catch (e) { safeResolve(false); }
          });
          req2.end(bodyMfa);
        } catch (e) { safeResolve(false); }
      });
      req1.end(JSON.stringify({ code: "" }));
    } catch (e) {
      safeResolve(false);
    }
  });
}

function fetchAndClaimVanity(guildId) {
  const sess = h2Sessions.find(s => s && !s.destroyed && !s.closed);
  if (!sess) return;

  try {
    const req = sess.request({
      ":method": "GET", ":path": `/api/v9/guilds/${guildId}/vanity-url`,
      ":authority": CONFIG.apiHost, ":scheme": "https",
      "authorization": CONFIG.patchToken, "user-agent": UA,
      "x-super-properties": XPROPS, "x-request-id": generateRequestId(),
    });

    let resp = "";
    req.on("data", c => { resp += c.toString(); });
    req.on("error", () => {});
    req.on("end", () => {
      try {
        const parsed = JSON.parse(resp);
        if (parsed && typeof parsed.code === "string" && parsed.code.length > 0) {
          console.log(`[VANITY TESPİT EDİLDİ] Çekilen vanity: ${parsed.code}`);
          patchVanity(parsed.code);
        }
      } catch (e) {}
    });
    req.end();
  } catch (e) {}
}

function patchVanity(vanity) {
  const body = `{"code":"${vanity}"}`;
  const bodyBuf = Buffer.from(body, "latin1");
  const len = bodyBuf.length;
  const mfa = mfaToken || "";

  console.log(`[PATCH İSTEĞİ] Alınmaya çalışılıyor: ${vanity}`);

  const tlsBuf = Buffer.from(
    `PATCH /api/v9/guilds/${CONFIG.ourGuildId}/vanity-url HTTP/1.1\r\n` +
    `Host: ${CONFIG.apiHost}\r\n` +
    `Authorization: ${CONFIG.patchToken}\r\n` +
    `Content-Type: application/json\r\n` +
    `Accept-Encoding: identity\r\n` +
    `User-Agent: ${UA}\r\n` +
    `X-Super-Properties: ${XPROPS}\r\n` +
    `X-Discord-Mfa-Authorization: ${mfa}\r\n` +
    `Content-Length: ${len}\r\n` +
    `Connection: keep-alive\r\n\r\n` + body,
    "latin1"
  );

  for (let i = h2Sessions.length - 1; i >= 0; i--) {
    const sess = h2Sessions[i];
    if (!sess || sess.destroyed || sess.closed) continue;
    try {
      const req = sess.request({
        ":method": "PATCH",
        ":path": `/api/v9/guilds/${CONFIG.ourGuildId}/vanity-url`,
        ":authority": CONFIG.apiHost, ":scheme": "https",
        "authorization": CONFIG.patchToken,
        "content-type": "application/json",
        "accept-encoding": "identity",
        "content-length": len,
        "user-agent": UA,
        "x-super-properties": XPROPS,
        "x-discord-mfa-authorization": mfa,
        "x-request-id": generateRequestId(),
      });
      req.on("error", () => {});
      let resp = "";
      req.on("data", c => { resp += c.toString("latin1"); });
      req.on("end", () => { console.log(`[H2 Yanıtı] ${resp.trim()}`); });
      req.end(bodyBuf);
    } catch (e) {}
  }

  for (let i = CONFIG.tlsSocketCount - 1; i >= 0; i--) {
    const s = tlsSockets[i];
    if (s && !s.destroyed) {
      try { s.write(tlsBuf); } catch (e) {}
    }
  }
}

// HTTP/2 Ping & Canlı Tutma Döngüsü (Her 15 Saniyede Bir)
setInterval(() => {
  for (let i = 0; i < h2Sessions.length; i++) {
    const sess = h2Sessions[i];
    if (sess && !sess.destroyed && !sess.closed) {
      let pingResponded = false;
      const pingTimer = setTimeout(() => {
        if (!pingResponded) {
          try { sess.destroy(); } catch (e) {}
        }
      }, 5000);

      try {
        sess.ping(Buffer.alloc(8), (err) => {
          pingResponded = true;
          clearTimeout(pingTimer);
          if (err) {
            try { sess.destroy(); } catch (e) {}
          }
        });
      } catch (e) {
        clearTimeout(pingTimer);
        try { sess.destroy(); } catch (e) {}
      }
    } else {
      h2Sessions[i] = createH2Session(i);
    }
  }
}, 15000);

// TLS Keep-Alive & Aktif Kontrol Döngüsü (Her 15 Saniyede Bir)
setInterval(() => {
  for (let i = 0; i < CONFIG.tlsSocketCount; i++) {
    const s = tlsSockets[i];
    if (s && !s.destroyed) {
      try {
        s.write(`GET /api/v9/gateway HTTP/1.1\r\nHost: ${CONFIG.apiHost}\r\nConnection: keep-alive\r\n\r\n`);
      } catch (e) {
        try { s.destroy(); } catch (err) {}
      }
    } else {
      createTLS(i);
    }
  }
}, 15000);

function connectGatewayListener(token, index) {
  let hbTimer = null, pingTimer = null, hbAcked = true;

  const cleanup = () => {
    if (hbTimer) clearInterval(hbTimer);
    if (pingTimer) clearInterval(pingTimer);
  };

  const sock = new WebSocket(CONFIG.wsUrl, {
    perMessageDeflate: false, skipUTF8Validation: true,
    followRedirects: false, rejectUnauthorized: false,
    maxRedirects: 0, handshakeTimeout: 30000,
    headers: { "User-Agent": UA },
  });

  sock.onopen = () => {
    if (sock.readyState === WebSocket.OPEN) {
      sock.send(JSON.stringify({
        op: 2,
        d: {
          token, intents: 1,
          properties: { os: "linux", browser: "chrome", device: "chrome" },
          guild_subscriptions: false, large_threshold: 0,
        },
      }));
    }
  };

  sock.onmessage = (msg) => {
    const data = msg.data;

    if (typeof data === "string" && data.includes("ENTITLEMENT_DELETE")) {
      if (detectedVanities.size > 0) {
        const vanity = Array.from(detectedVanities.keys())[0];
        patchVanity(vanity);
        detectedVanities.delete(vanity);
      }
      try {
        const p = JSON.parse(data);
        const guildId = p?.d?.guild_id;
        if (guildId) fetchAndClaimVanity(guildId);
      } catch (e) {}
      return;
    }

    if (typeof data === "string" && data.includes("GUILD_UPDATE")) {
      try {
        const p = JSON.parse(data);
        if (p.t === "GUILD_UPDATE" && p.d?.vanity_url_code) {
          detectedVanities.set(p.d.vanity_url_code, true);
        }
      } catch (e) {}
      return;
    }

    try {
      const p = JSON.parse(data);
      if (p.op === 11) { hbAcked = true; return; }
      if (p.op === 7 || p.op === 9) { sock.close(); return; }
      if (p.op === 10) {
        cleanup();
        hbAcked = true;
        hbTimer = setInterval(() => {
          if (sock.readyState !== WebSocket.OPEN) return;
          if (!hbAcked) return sock.terminate();
          hbAcked = false;
          try { sock.send(heartbeatBuffer); } catch (e) {}
        }, p.d.heartbeat_interval);
      }
    } catch (e) {}
  };

  sock.onerror = () => {
    cleanup();
    try { sock.close(); } catch (e) {}
  };

  sock.onclose = () => {
    cleanup();
    setTimeout(() => connectGatewayListener(token, index), 1000);
  };

  pingTimer = setInterval(() => {
    if (sock.readyState !== WebSocket.OPEN) return;
    try { sock.ping(); } catch (e) {}
  }, 30000);
}

function waitForH2Session(ms = 10000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const t = setInterval(() => {
      if (h2Sessions.find(s => s && !s.destroyed && !s.closed)) { clearInterval(t); resolve(true); }
      else if (Date.now() - start > ms) { clearInterval(t); resolve(false); }
    }, 100);
  });
}

async function initialize() {
  loadTokens();
  for (let i = 0; i < CONFIG.tlsSocketCount; i++) createTLS(i);
  for (let i = 0; i < CONFIG.h2SessionCount; i++) h2Sessions[i] = createH2Session(i);
  await waitForH2Session();
  await getMfaToken();
  tokens.forEach((token, index) => {
    setTimeout(() => connectGatewayListener(token, index), index * 100);
  });
  setInterval(() => getMfaToken(), CONFIG.mfaRefreshInterval);
}

process.on("SIGINT", () => { clearInterval(_keepAlive); process.exit(0); });
process.on("uncaughtException", (err) => { console.error("[uncaughtException]", err); });
process.on("unhandledRejection", (reason) => { console.error("[unhandledRejection]", reason); });

initialize().catch(() => process.exit(0));
