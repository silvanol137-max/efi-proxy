const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const {
  EFI_CLIENT_ID,
  EFI_CLIENT_SECRET,
  PROXY_TOKEN,
  EFI_SANDBOX
} = process.env;

if (!EFI_CLIENT_ID || !EFI_CLIENT_SECRET || !PROXY_TOKEN) {
  console.error("Variáveis obrigatórias faltando");
  process.exit(1);
}

const baseURL = EFI_SANDBOX === "true"
  ? "https://pix-h.api.efipay.com.br"
  : "https://pix.api.efipay.com.br";

app.use((req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || auth !== `Bearer ${PROXY_TOKEN}`) {
    return res.status(401).json({ error: "Não autorizado" });
  }

  next();
});

app.post("/auth", async (req, res) => {
  try {
    const response = await axios.post(
      `${baseURL}/oauth/token`,
      "grant_type=client_credentials",
      {
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
    console.error("Erro:", error.response?.data || error.message);

    res.status(500).json({
      error: "Erro ao autenticar",
      detalhe: error.response?.data || error.message,
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Proxy rodando na porta ${PORT}`);
});
