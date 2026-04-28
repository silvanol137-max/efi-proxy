# Efí mTLS Proxy

Pequeno servidor Node.js que faz o handshake mTLS com a API Pix da Efí em nome do app Lovable. Necessário porque o runtime do Lovable (Cloudflare Worker) não suporta mTLS via `node:https`.

## O que o proxy faz

| Endpoint                  | Método | Auth                | Função                                          |
|---------------------------|--------|---------------------|-------------------------------------------------|
| `/`                       | GET    | público             | Health check                                    |
| `/auth`                   | POST   | Bearer PROXY_TOKEN  | Testa OAuth client_credentials na Efí           |
| `/cob`                    | POST   | Bearer PROXY_TOKEN  | Cria cobrança Pix imediata + retorna QR Code    |
| `/cob/:txid`              | GET    | Bearer PROXY_TOKEN  | Consulta status da cobrança                     |
| `/webhook/efi-pix`        | POST   | público (HMAC opc.) | Recebe webhook da Efí e repassa pro app Lovable |

---

## Deploy no Railway (passo a passo)

Tempo: ~5 minutos.

### 1. Crie a conta e o projeto

1. Acesse https://railway.app e faça login (GitHub funciona).
2. **New Project** → **Deploy from GitHub repo**.
   - Suba a pasta `efi-proxy` deste projeto pra um repositório seu no GitHub (pode ser repo separado ou monorepo).
   - Selecione esse repositório.
3. Se for monorepo, em **Settings → Service → Root Directory**, defina `efi-proxy`.

Railway detecta Node.js automaticamente e roda `npm install` + `npm start`.

### 2. Variáveis de ambiente

Em **Variables**, adicione:

| Nome                    | Valor                                                                                  |
|-------------------------|----------------------------------------------------------------------------------------|
| `PROXY_TOKEN`           | Inventa um token longo aleatório. Ex: rode `openssl rand -hex 32` no terminal.         |
| `EFI_CLIENT_ID`         | Client ID da sua aplicação Efí (Produção)                                              |
| `EFI_CLIENT_SECRET`     | Client Secret da MESMA aplicação                                                       |
| `EFI_CERT_BASE64`       | Conteúdo do `.p12` em base64. Gere com `base64 -i certificado.p12 \| tr -d '\n'`       |
| `EFI_CERT_PASSWORD`     | (opcional) senha do `.p12`. Deixe vazio se não tiver.                                  |
| `FORWARD_WEBHOOK_URL`   | `https://gsminis.lovable.app/api/public/webhook/efi-pix`                               |
| `EFI_WEBHOOK_HMAC`      | (opcional) string secreta. Se setada, exigida como `?hmac=...` na URL pela Efí        |

### 3. Domínio público

1. **Settings → Networking → Generate Domain**.
2. Anote a URL gerada — ex: `https://efi-proxy-production.up.railway.app`.
3. Teste: `curl https://SEU-PROXY.up.railway.app/` deve retornar `{"ok":true,"service":"efi-proxy",...}` mostrando o tipo e tamanho do certificado carregado.

### 4. Configure o Lovable

No app Lovable, adicione 2 secrets:

| Nome              | Valor                                                  |
|-------------------|--------------------------------------------------------|
| `EFI_PROXY_URL`   | URL do proxy SEM barra final (ex: `https://efi-proxy-production.up.railway.app`) |
| `EFI_PROXY_TOKEN` | mesmo valor do `PROXY_TOKEN` que você definiu no Railway |

(O `EFI_CLIENT_ID`, `EFI_CLIENT_SECRET`, `EFI_CERT_BASE64` e `EFI_CERT_PASSWORD` no Lovable não são mais usados — podem ser removidos depois que tudo estiver funcionando.)

### 5. Cadastre o webhook na Efí

No painel da Efí (**API → Pix → Webhooks**), cadastre a URL:

```
https://SEU-PROXY.up.railway.app/webhook/efi-pix
```

Se você setou `EFI_WEBHOOK_HMAC`, anexe `?hmac=<seu_token>` à URL.

A Efí faz uma chamada GET inicial pra validar (o proxy responde 200). Depois envia POST a cada Pix recebido — o proxy valida e repassa pro Lovable em `FORWARD_WEBHOOK_URL` com `Authorization: Bearer <PROXY_TOKEN>`.

### 6. Teste

No painel admin do app, clique em **"Testar autenticação Efí"**. Deve retornar:

```
✅ Autenticado com sucesso
Ambiente: producao
Base URL: https://pix.api.efipay.com.br
Certificado: PFX (3127 bytes)  ← veja no log do Railway na startup
Token expira em: 3600s
```

Se aparecer ❌, o erro vem direto da Efí (sanitizado) e os logs do Railway mostram o detalhe completo.

---

## Custos Railway

- **Trial**: $5 grátis no primeiro mês.
- **Hobby plan**: $5/mês inclui $5 de uso. Esse proxy consome ~$1–2/mês (256MB RAM, ocioso quase o tempo todo).
- O Railway **não dorme** o serviço (diferente do Render free), então o webhook responde sempre instantâneo.

## Atualizando o proxy

Push no GitHub → Railway redeploya automaticamente. Mantenha o `PROXY_TOKEN` igual nos 2 lados.
