const express = require("express");
const https = require("https");
const axios = require("axios");

const app = express();
app.use(express.json());

// ===== CONFIG =====
const {
  EFI_CLIENT_ID,
  EFI_CLIENT_SECRET,
  EFI_CERT_BASE64,
  EFI_SANDBOX,
  PROXY_TOKEN,
  EFI_CERT_PASSWORD
} = process.env;

// ===== VALIDAR VARIÁVEIS =====
if (!EFI_CLIENT_ID || !EFI_CLIENT_SECRET || !EFI_CERT_BASE64 || !PROXY_TOKEN) {
  console.error("Variáveis obrigatórias faltando");
  process.exit(1);
}

// ===== CERTIFICADO =====
let certBuffer;

try {
  certBuffer = Buffer.from(EFI_CERT_BASE64, "base64");
  console.log("Certificado carregado:", certBuffer.length, "bytes");
} catch (e) {
  console.error("Erro ao carregar certificado:", e.message);
  process.exit(1);
}

// ===== AGENT HTTPS =====
const agent = new https.Agent({
  pfx: certBuffer,
  passphrase: EFI_CERT_PASSWORD || undefined,
  rejectUnauthorized: true,
});

// ===== BASE URL =====
const baseURL = EFI_SANDBOX === "true"
  ? "https://pix-h.api.efipay.com.br"
  : "https://pix.api.efipay.com.br";

console.log("Ambiente:", EFI_SANDBOX === "true" ? "SANDBOX" : "PRODUÇÃO");

// ===== MIDDLEWARE TOKEN =====
app.use((req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || auth !== `Bearer ${PROXY_TOKEN}`) {
    return res.status(401).json({ error: "Não autorizado" });
  }

  next();
});

// ===== ROTA AUTH =====
app.post("/auth", async (req, res) => {
  try {
    const response = await axios.post(
      `${baseURL}/oauth/token`,
      "grant_type=client_credentials",
      {
        httpsAgent: agent,
        headers: {
          Authorization:
            "Basic " +
            Buffer.from(`${EFI_CLIENT_ID}:${EFI_CLIENT_SECRET}`).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("Erro autenticação:", error.message);

    res.status(500).json({
      error: "Erro ao autenticar",
      detalhe: error.message,
    });
  }
});

// ===== START =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Proxy rodando na porta ${PORT}`);
});
