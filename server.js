// ============================================================================
// Efí Bank Pix — Proxy mTLS externo
// ----------------------------------------------------------------------------
// Por que existe: o app Lovable roda em Cloudflare Worker, que NÃO suporta
// mTLS via node:https. Este proxy roda em Node.js puro (Railway/Render/Fly/VPS),
// recebe chamadas Bearer-autenticadas do app e fala com a Efí usando o .p12.
//
// Endpoints:
//   GET  /                   -> health check (público)
//   POST /auth               -> testa OAuth client_credentials      (Bearer)
//   POST /cob                -> cria cobrança Pix imediata + QR     (Bearer)
//   GET  /cob/:txid          -> consulta status da cobrança         (Bearer)
//   POST /webhook/efi-pix    -> recebe webhook da Efí e repassa     (público + HMAC opcional)
//
// O webhook valida (1) HMAC opcional via query string e (2) repassa o payload
// para a aplicação Lovable em FORWARD_WEBHOOK_URL com header Bearer.
// ============================================================================

import http from "node:http";
import https from "node:https";

const PORT = process.env.PORT || 3000;

// --- Auth do proxy ----------------------------------------------------------
const PROXY_TOKEN = process.env.PROXY_TOKEN;

// --- Credenciais Efí --------------------------------------------------------
const CLIENT_ID = process.env.EFI_CLIENT_ID;
const CLIENT_SECRET = process.env.EFI_CLIENT_SECRET;
const CERT_BASE64 = process.env.EFI_CERT_BASE64;
const CERT_PASSWORD = process.env.EFI_CERT_PASSWORD || undefined;

// --- Webhook ----------------------------------------------------------------
// Para onde o proxy repassa o webhook recebido da Efí.
// Normalmente: https://gsminis.lovable.app/api/public/webhook/efi-pix
const FORWARD_WEBHOOK_URL = process.env.FORWARD_WEBHOOK_URL;
// Token opcional adicionado como ?hmac=... pela Efí. Se setado, exigimos match.
const WEBHOOK_HMAC = process.env.EFI_WEBHOOK_HMAC || null;

const SANDBOX_URL = "https://pix-h.api.efipay.com.br";
const PRODUCTION_URL = "https://pix.api.efipay.com.br";

if (!PROXY_TOKEN || !CLIENT_ID || !CLIENT_SECRET || !CERT_BASE64) {
  console.error(
    "[FATAL] Variáveis obrigatórias: PROXY_TOKEN, EFI_CLIENT_ID, EFI_CLIENT_SECRET, EFI_CERT_BASE64"
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Carrega certificado .p12 ou PEM
// ---------------------------------------------------------------------------
function parseCert() {
  const clean = CERT_BASE64.trim().replace(/^data:[^,]+,/, "").replace(/\s/g, "");
  const decoded = Buffer.from(clean, "base64");
  const asText = decoded.toString("utf8");
  if (asText.includes("-----BEGIN")) {
    return {
      tls: { cert: asText, key: asText, passphrase: CERT_PASSWORD },
      info: { tipo: "PEM", bytes: Buffer.byteLength(asText, "utf8") },
    };
  }
  return {
    tls: { pfx: decoded, passphrase: CERT_PASSWORD },
    info: { tipo: "PFX", bytes: decoded.length },
  };
}
const CERT = parseCert();

// ---------------------------------------------------------------------------
// HTTPS com mTLS
// ---------------------------------------------------------------------------
function efiFetch(baseUrl, path, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(baseUrl + path);
    const body = options.body;
    const headers = {
      Accept: "application/json",
      "User-Agent": "efi-proxy/1.0",
      ...(options.headers || {}),
    };
    if (body) headers["Content-Length"] = Buffer.byteLength(body);

    const req = https.request(
      {
        hostname: u.hostname,
        port: 443,
        path: u.pathname + u.search,
        method: options.method || "GET",
        headers,
        ...CERT.tls,
        minVersion: "TLSv1.2",
        timeout: 30000,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.setTimeout(30000, () => req.destroy(new Error("Timeout Efí")));
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// OAuth token cache
// ---------------------------------------------------------------------------
let tokenCache = { token: null, expires: 0, baseUrl: null, json: null };

async function getToken(sandbox) {
  const baseUrl = sandbox ? SANDBOX_URL : PRODUCTION_URL;
  if (
    tokenCache.token &&
    tokenCache.baseUrl === baseUrl &&
    tokenCache.expires > Date.now() + 30000
  ) {
    return { token: tokenCache.token, baseUrl, json: tokenCache.json };
  }
  const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const res = await efiFetch(baseUrl, "/oauth/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ grant_type: "client_credentials" }),
  });
  if (res.status !== 200) {
    const err = new Error(`Auth Efí HTTP ${res.status}`);
    err.status = res.status;
    err.bodyRaw = res.body;
    throw err;
  }
  const json = JSON.parse(res.body);
  tokenCache = {
    token: json.access_token,
    baseUrl,
    expires: Date.now() + json.expires_in * 1000,
    json,
  };
  return { token: json.access_token, baseUrl, json };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

function sanitize(str) {
  return String(str || "").replace(/[A-Za-z0-9+/=]{60,}/g, "[REDACTED]");
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // --- Health check (público) ------------------------------------------
    if (req.method === "GET" && url.pathname === "/") {
      return send(res, 200, {
        ok: true,
        service: "efi-proxy",
        cert: CERT.info,
        time: new Date().toISOString(),
      });
    }

    // --- Webhook Efí (público, validação por HMAC) -----------------------
    // Efí faz GET inicial sem corpo para validar o endpoint.
    if (url.pathname === "/webhook/efi-pix") {
      if (req.method === "GET") return send(res, 200, { ok: true });
      if (req.method === "POST") {
        if (WEBHOOK_HMAC) {
          const got = url.searchParams.get("hmac");
          if (got !== WEBHOOK_HMAC) return send(res, 401, { erro: "Invalid HMAC" });
        }
        const raw = await readBody(req);
        if (!FORWARD_WEBHOOK_URL) {
          console.warn("[webhook] FORWARD_WEBHOOK_URL não configurado, descartando");
          return send(res, 200, { received: true, forwarded: false });
        }
        // Repassa para o app Lovable autenticado com Bearer
        try {
          const fwd = await fetch(FORWARD_WEBHOOK_URL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${PROXY_TOKEN}`,
              "X-Forwarded-By": "efi-proxy",
            },
            body: raw,
          });
          console.log(`[webhook] forwarded -> ${fwd.status}`);
          return send(res, 200, { received: true, forwarded: true, upstream: fwd.status });
        } catch (e) {
          console.error("[webhook] forward failed:", e);
          // Devolvemos 200 pra Efí não reentregar. Ela já fez o trabalho dela.
          return send(res, 200, { received: true, forwarded: false, erro: String(e.message || e) });
        }
      }
      return send(res, 405, { erro: "Method Not Allowed" });
    }

    // --- A partir daqui exige Bearer PROXY_TOKEN -------------------------
    const auth = req.headers.authorization || "";
    if (auth !== `Bearer ${PROXY_TOKEN}`) return send(res, 401, { erro: "Unauthorized" });

    const sandbox = (req.headers["x-efi-sandbox"] || "false") === "true";

    // --- POST /auth -------------------------------------------------------
    if (req.method === "POST" && url.pathname === "/auth") {
      try {
        const { json, baseUrl } = await getToken(sandbox);
        return send(res, 200, {
          ok: true,
          baseUrl,
          certInfo: CERT.info,
          expires_in: json.expires_in,
          token_type: json.token_type,
          scope: json.scope,
        });
      } catch (e) {
        return send(res, 200, {
          ok: false,
          baseUrl: sandbox ? SANDBOX_URL : PRODUCTION_URL,
          certInfo: CERT.info,
          status: e.status,
          erro: sanitize(e.bodyRaw || e.message).slice(0, 500),
        });
      }
    }

    // --- POST /cob — cria cobrança e retorna QR --------------------------
    if (req.method === "POST" && url.pathname === "/cob") {
      const raw = await readBody(req);
      const input = JSON.parse(raw);
      const { token, baseUrl } = await getToken(sandbox);
      const body = {
        calendario: { expiracao: input.expiracaoSegundos },
        devedor: input.cpf ? { cpf: input.cpf, nome: input.nome } : undefined,
        valor: { original: input.valor },
        chave: input.chave,
        solicitacaoPagador: input.descricao,
      };
      const cob = await efiFetch(baseUrl, `/v2/cob/${input.txid}`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (cob.status !== 200 && cob.status !== 201) {
        return send(res, cob.status, { erro: sanitize(cob.body) });
      }
      const cobJson = JSON.parse(cob.body);
      const qr = await efiFetch(baseUrl, `/v2/loc/${cobJson.loc.id}/qrcode`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (qr.status !== 200) return send(res, qr.status, { erro: sanitize(qr.body) });
      const qrJson = JSON.parse(qr.body);
      return send(res, 200, {
        txid: input.txid,
        qrCodeImage: qrJson.imagemQrcode,
        pixCopiaECola: qrJson.qrcode,
        loc: cobJson.loc.location,
      });
    }

    // --- GET /cob/:txid ---------------------------------------------------
    const m = url.pathname.match(/^\/cob\/([^/]+)$/);
    if (req.method === "GET" && m) {
      const { token, baseUrl } = await getToken(sandbox);
      const r = await efiFetch(baseUrl, `/v2/cob/${m[1]}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });
      return send(res, r.status, r.body || "{}");
    }

    return send(res, 404, { erro: "Not Found" });
  } catch (e) {
    console.error("[unhandled]", e);
    return send(res, 500, { erro: String(e.message || e) });
  }
});

server.listen(PORT, () => {
  console.log(`efi-proxy listening on :${PORT}`);
  console.log(`Certificado: ${CERT.info.tipo} (${CERT.info.bytes} bytes)`);
  console.log(`Webhook forward: ${FORWARD_WEBHOOK_URL || "(não configurado)"}`);
});
