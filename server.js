const http = require('http');
const https = require('https');
const crypto = require('crypto');

// ═══════════════════════ CORA mTLS PROXY ═══════════════════════
// Proxy externo que faz a conexão mTLS com a API da Cora.
// O Base44 (Deno Deploy) não consegue fazer mTLS diretamente,
// então este proxy Node.js faz a ponte.
//
// Segurança: shared secret (PROXY_API_KEY) validada em cada requisição.
// Os certificados são recebidos por requisição (uma empresa = um certificado).

const PROXY_API_KEY = process.env.PROXY_API_KEY || 'cora-proxy-change-this-key';
const HOTMART_PROXY_API_KEY = process.env.HOTMART_PROXY_API_KEY || PROXY_API_KEY;
const PORT = process.env.PORT || 3001;

// ── Cache de tokens Hotmart (evita chamadas repetidas ao /security/oauth/token) ──
const hotmartTokenCache = new Map(); // key: clientId → { token, expiresAt }
const HOTMART_TOKEN_TTL_MS = 60 * 60 * 1000; // 60 minutos

// ═══════════════════════ HOTMART PROXY ═══════════════════════
// A Hotmart bloqueia (invalid_parameter) chamadas vindas do range de IPs do Deno Deploy da Base44.
// Este proxy Node.js faz as chamadas à API da Hotmart de um IP externo, contornando o bloqueio.
//
// Segurança: shared secret (HOTMART_PROXY_API_KEY) validada em cada requisição.
// Auth Hotmart: OAuth2 client_credentials (Basic base64(client_id:client_secret)).

/**
 * Faz uma requisição HTTPS simples (sem mTLS) — usada para a API da Hotmart,
 * que é autenticada via Bearer token (OAuth2), não por certificado.
 */
function httpsRequest({ hostname, path, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port: 443,
      path,
      method: method || 'GET',
      headers: headers || {},
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(45000, () => {
      req.destroy(new Error('Timeout na requisição à Hotmart'));
    });
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Processa uma requisição proxy para a Hotmart.
 * Recebe credenciais + dados da chamada API, faz a autenticação OAuth2 e retorna o resultado.
 */
async function handleHotmartProxy(payload) {
  const { client_id, client_secret, method, path: hotmartPath, params, body: hotmartBody } = payload;

  if (!client_id || !client_secret) {
    return { status: 400, data: { error: 'client_id e client_secret são obrigatórios' } };
  }
  if (!hotmartPath) {
    return { status: 400, data: { error: 'path é obrigatório' } };
  }

  // ── Passo 1: Obter access_token (com cache) ──
  const cacheKey = client_id;
  const cached = hotmartTokenCache.get(cacheKey);
  let accessToken = null;
  if (cached && cached.expiresAt > Date.now()) {
    accessToken = cached.token;
  }

  if (!accessToken) {
    const basicAuth = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
    const tokenUrl = `https://api-sec-vlc.hotmart.com/security/oauth/token?grant_type=client_credentials&client_id=${encodeURIComponent(client_id)}&client_secret=${encodeURIComponent(client_secret)}`;
    const tokenRes = await httpsRequest({
      hostname: 'api-sec-vlc.hotmart.com',
      path: `/security/oauth/token?grant_type=client_credentials&client_id=${encodeURIComponent(client_id)}&client_secret=${encodeURIComponent(client_secret)}`,
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/json',
      },
    });

    if (tokenRes.status !== 200) {
      let errData;
      try { errData = JSON.parse(tokenRes.body); } catch { errData = tokenRes.body; }
      return { status: 401, data: { error: 'Falha na autenticação com a Hotmart', hotmart_status: tokenRes.status, hotmart_response: errData } };
    }

    let tokenData;
    try { tokenData = JSON.parse(tokenRes.body); } catch {
      return { status: 502, data: { error: 'Resposta de token inválida', raw: tokenRes.body } };
    }

    accessToken = tokenData.access_token;
    if (!accessToken) {
      return { status: 502, data: { error: 'Token de acesso não recebido', resposta: tokenData } };
    }
    hotmartTokenCache.set(cacheKey, { token: accessToken, expiresAt: Date.now() + HOTMART_TOKEN_TTL_MS });
  }

  // ── Passo 2: Chamar a API da Hotmart ──
  let fullPath = hotmartPath;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') searchParams.set(k, String(v));
    }
    const qs = searchParams.toString();
    if (qs) fullPath += '?' + qs;
  }

  const upperMethod = (method || 'GET').toUpperCase();
  const apiHeaders = {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
  };
  let apiBodyStr;
  if (hotmartBody && upperMethod !== 'GET') {
    apiBodyStr = JSON.stringify(hotmartBody);
  }

  let apiRes = await httpsRequest({
    hostname: 'developers.hotmart.com',
    path: fullPath,
    method: upperMethod,
    headers: apiHeaders,
    body: apiBodyStr,
  });

  // ── Se 401, invalida cache e refaz token ──
  if (apiRes.status === 401) {
    hotmartTokenCache.delete(cacheKey);
    const basicAuth = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
    const tokenRes = await httpsRequest({
      hostname: 'api-sec-vlc.hotmart.com',
      path: `/security/oauth/token?grant_type=client_credentials&client_id=${encodeURIComponent(client_id)}&client_secret=${encodeURIComponent(client_secret)}`,
      method: 'POST',
      headers: { 'Authorization': `Basic ${basicAuth}`, 'Content-Type': 'application/json' },
    });
    if (tokenRes.status === 200) {
      let tokenData;
      try { tokenData = JSON.parse(tokenRes.body); } catch { tokenData = null; }
      if (tokenData?.access_token) {
        accessToken = tokenData.access_token;
        hotmartTokenCache.set(cacheKey, { token: accessToken, expiresAt: Date.now() + HOTMART_TOKEN_TTL_MS });
        apiHeaders.Authorization = `Bearer ${accessToken}`;
        apiRes = await httpsRequest({
          hostname: 'developers.hotmart.com',
          path: fullPath,
          method: upperMethod,
          headers: apiHeaders,
          body: apiBodyStr,
        });
      }
    }
  }

  let responseData;
  try { responseData = JSON.parse(apiRes.body); } catch { responseData = apiRes.body; }

  return { status: apiRes.status, data: responseData };
}

// ── Cache de tokens Cora (evita rate-limit no endpoint /token) ──
// Cora tokens duram ~1h; cacheamos por 50min para reutilizar entre chamadas.
const tokenCache = new Map(); // key: client_id|ambiente → { token, expiresAt }
const TOKEN_TTL_MS = 50 * 60 * 1000; // 50 minutos
// Deduplica chamadas de token em paralelo (race condition no cold start)
const tokenFetchInFlight = new Map(); // key: client_id|ambiente → Promise<token>

/**
 * Faz uma requisição HTTPS com mTLS (client certificate) para a Cora.
 * Usa https.request nativo do Node.js — apresenta o certificado corretamente.
 */
function mTlsRequest({ hostname, path, method, headers, body, cert, key }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port: 443,
      path,
      method: method || 'GET',
      headers: headers || {},
      cert,
      key,
      rejectUnauthorized: true,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });

    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error('Timeout na requisição à Cora'));
    });

    if (body) req.write(body);
    req.end();
  });
}

/**
 * Processa uma requisição proxy para a Cora.
 * Recebe as credenciais + dados da chamada API, faz mTLS, retorna o resultado.
 */
async function handleCoraProxy(payload) {
  const {
    client_id,
    cert_pem,
    private_key,
    ambiente,
    method,
    path: coraPath,
    body: coraBody,
    params,
    idempotency_key,
  } = payload;

  if (!client_id || !cert_pem || !private_key) {
    return { status: 400, data: { error: 'client_id, cert_pem e private_key são obrigatórios' } };
  }

  if (!coraPath) {
    return { status: 400, data: { error: 'path é obrigatório' } };
  }

  const hostname =
    ambiente === 'producao'
      ? 'matls-clients.api.cora.com.br'
      : 'matls-clients.api.stage.cora.com.br';

  // ── Passo 1: Obter access_token via mTLS (com cache) ──
  const cacheKey = client_id + '|' + (ambiente || 'stage');
  const cached = tokenCache.get(cacheKey);
  let accessToken = null;

  if (cached && cached.expiresAt > Date.now()) {
    accessToken = cached.token;
  }

  if (!accessToken) {
    // Deduplica: se já existe uma busca de token em andamento, aguarda ela
    if (tokenFetchInFlight.has(cacheKey)) {
      try {
        accessToken = await tokenFetchInFlight.get(cacheKey);
      } catch (e) {
        return { status: 502, data: { error: 'Falha ao aguardar token em andamento: ' + e.message } };
      }
    } else {
      const fetchPromise = (async () => {
        const tokenBodyStr = 'grant_type=client_credentials&client_id=' + client_id;
        const tokenRes = await mTlsRequest({
          hostname,
          path: '/token',
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: tokenBodyStr,
          cert: cert_pem,
          key: private_key,
        });

        if (tokenRes.status !== 200) {
          throw new Error(JSON.stringify({
            error: 'Falha na autenticação com a Cora',
            cora_status: tokenRes.status,
            cora_response: tokenRes.body,
            hostname_usado: hostname,
          }));
        }

        let tokenData;
        try {
          tokenData = JSON.parse(tokenRes.body);
        } catch {
          throw new Error(JSON.stringify({ error: 'Resposta de token inválida', raw: tokenRes.body }));
        }

        const tok = tokenData.access_token;
        if (!tok) {
          throw new Error(JSON.stringify({ error: 'Token de acesso não recebido', resposta: tokenData }));
        }

        tokenCache.set(cacheKey, { token: tok, expiresAt: Date.now() + TOKEN_TTL_MS });
        return tok;
      })();

      tokenFetchInFlight.set(cacheKey, fetchPromise);

      try {
        accessToken = await fetchPromise;
      } catch (e) {
        tokenFetchInFlight.delete(cacheKey);
        let errData;
        try { errData = JSON.parse(e.message); } catch { errData = { error: e.message }; }
        return { status: 502, data: errData };
      } finally {
        tokenFetchInFlight.delete(cacheKey);
      }
    }
  }

  // ── Passo 2: Chamar a API da Cora via mTLS ──
  let fullPath = coraPath;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') searchParams.set(k, String(v));
    }
    const qs = searchParams.toString();
    if (qs) fullPath += '?' + qs;
  }

  const apiHeaders = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
  };
  if (idempotency_key) {
    apiHeaders['Idempotency-Key'] = idempotency_key;
  }

  let apiBodyStr;
  const upperMethod = (method || 'GET').toUpperCase();
  if (coraBody && upperMethod !== 'GET') {
    apiHeaders['Content-Type'] = 'application/json';
    apiBodyStr = JSON.stringify(coraBody);
  }

  let apiRes = await mTlsRequest({
    hostname,
    path: fullPath,
    method: upperMethod,
    headers: apiHeaders,
    body: apiBodyStr,
    cert: cert_pem,
    key: private_key,
  });

  // ── Se o token em cache expirou (401), invalida e refaz com token novo ──
  if (apiRes.status === 401) {
    tokenCache.delete(cacheKey);
    let retryToken = null;
    if (tokenFetchInFlight.has(cacheKey)) {
      try { retryToken = await tokenFetchInFlight.get(cacheKey); } catch {}
    } else {
      const retryTokenBodyStr = 'grant_type=client_credentials&client_id=' + client_id;
      const retryFetch = (async () => {
        const retryTokenRes = await mTlsRequest({
          hostname,
          path: '/token',
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: retryTokenBodyStr,
          cert: cert_pem,
          key: private_key,
        });
        if (retryTokenRes.status !== 200) throw new Error('retry failed');
        let retryTokenData;
        try { retryTokenData = JSON.parse(retryTokenRes.body); } catch { retryTokenData = null; }
        const tok = retryTokenData?.access_token;
        if (tok) tokenCache.set(cacheKey, { token: tok, expiresAt: Date.now() + TOKEN_TTL_MS });
        return tok;
      })();
      tokenFetchInFlight.set(cacheKey, retryFetch);
      try { retryToken = await retryFetch; } catch {} finally { tokenFetchInFlight.delete(cacheKey); }
    }
    if (retryToken) {
      apiHeaders.Authorization = `Bearer ${retryToken}`;
      apiRes = await mTlsRequest({
        hostname,
        path: fullPath,
        method: upperMethod,
        headers: apiHeaders,
        body: apiBodyStr,
        cert: cert_pem,
        key: private_key,
      });
    }
  }

  let responseData;
  try {
    responseData = JSON.parse(apiRes.body);
  } catch {
    responseData = apiRes.body;
  }

  return { status: apiRes.status, data: responseData };
}

// ═══════════════════════ SERPRO mTLS PROXY ═══════════════════════
// O SERPRO (API Integra Contador) exige mTLS com certificado e-CNPJ (.pfx/.p12).
// O Deno Deploy não consegue fazer mTLS, então este proxy faz a ponte.
//
// Fluxo: authenticate (mTLS) → access_token + jwt_token → chamada API (mTLS)

// ── Cache de tokens SERPRO (evita reautenticar a cada chamada) ──
const serproTokenCache = new Map(); // key: consumerKey|ambiente → { accessToken, jwtToken, expiresAt }
const SERPRO_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutos (tokens duram ~33min)

/**
 * Faz uma requisição HTTPS com mTLS usando certificado PFX (SERPRO).
 * Diferente da Cora (que usa PEM+key), o SERPRO usa .pfx/.p12 com passphrase.
 */
function mTlsRequestPfx({ hostname, path, method, headers, body, pfx, passphrase }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port: 443,
      path,
      method: method || 'POST',
      headers: headers || {},
      pfx,
      passphrase,
      rejectUnauthorized: true,
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error('Timeout na requisição ao SERPRO'));
    });
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Processa uma requisição proxy para o SERPRO (API Integra Contador).
 * Recebe credenciais + certificado PFX, faz mTLS, retorna o resultado.
 */
async function handleSerproProxy(payload) {
  const {
    consumer_key,
    consumer_secret,
    cert_pfx_base64,
    cert_senha,
    ambiente,
    test_only = true,
    path: serproPath,
    body: serproBody,
  } = payload;

  if (!consumer_key || !consumer_secret || !cert_pfx_base64) {
    return { status: 400, data: { error: 'consumer_key, consumer_secret e cert_pfx_base64 são obrigatórios' } };
  }

  // Decodificar PFX
  let pfxBuffer;
  try {
    pfxBuffer = Buffer.from(cert_pfx_base64, 'base64');
  } catch (e) {
    return { status: 400, data: { error: 'Certificado PFX inválido (base64 corrompido)' } };
  }

  // ── Pré-validação do PFX: tenta carregar o secure context para detectar erros cedo ──
  try {
    require('tls').createSecureContext({ pfx: pfxBuffer, passphrase: cert_senha });
  } catch (e) {
    return {
      status: 400,
      data: {
        error: 'Certificado PFX não pôde ser carregado',
        detalhe: e.message,
        code: e.code,
        hint: e.message === 'unsupported' || (e.message && e.message.includes('unsupported'))
          ? 'O algoritmo do PFX provavelmente não é suportado pelo OpenSSL 3 do Node.js 18. Adicione NODE_OPTIONS=--openssl-legacy-provider nas variáveis de ambiente do Railway, ou reexporte o certificado com algoritmo moderno (AES-256).'
          : 'Verifique se o base64 está correto e se a senha do certificado está correta.',
      }
    };
  }

  // ── Passo 1: Autenticar no SERPRO (mTLS) ──
  const cacheKey = consumer_key + '|' + (ambiente || 'trial');
  const cached = serproTokenCache.get(cacheKey);
  let accessToken = null;
  let jwtToken = null;

  if (cached && cached.expiresAt > Date.now()) {
    accessToken = cached.accessToken;
    jwtToken = cached.jwtToken;
  }

  if (!accessToken) {
    const basicAuth = Buffer.from(`${consumer_key}:${consumer_secret}`).toString('base64');
    let authRes;
    try {
      authRes = await mTlsRequestPfx({
        hostname: 'autenticacao.sapi.serpro.gov.br',
        path: '/authenticate',
        method: 'POST',
        headers: {
          'Authorization': `Basic ${basicAuth}`,
          'role-type': 'TERCEIROS',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
        pfx: pfxBuffer,
        passphrase: cert_senha,
      });
    } catch (e) {
      return {
        status: 502,
        data: {
          error: 'Erro na conexão mTLS com o SERPRO',
          detalhe: e.message,
          code: e.code,
          hint: e.message === 'unsupported' || (e.message && e.message.includes('unsupported'))
            ? 'Algoritmo do PFX não suportado pelo OpenSSL 3. Adicione NODE_OPTIONS=--openssl-legacy-provider no Railway.'
            : 'Verifique conectividade de rede e validade do certificado.',
        }
      };
    }

    if (authRes.status !== 200) {
      let errData;
      try { errData = JSON.parse(authRes.body); } catch { errData = authRes.body; }
      return {
        status: 401,
        data: {
          error: 'Falha na autenticação SERPRO',
          serpro_status: authRes.status,
          serpro_response: errData,
          hint: 'Verifique Consumer Key, Consumer Secret, certificado digital e senha. O certificado deve ser o mesmo e-CNPJ usado na contratação.',
        }
      };
    }

    let authData;
    try { authData = JSON.parse(authRes.body); } catch {
      return { status: 502, data: { error: 'Resposta de autenticação inválida', raw: authRes.body } };
    }

    accessToken = authData.access_token;
    jwtToken = authData.jwt_token;

    if (!accessToken) {
      return { status: 502, data: { error: 'Token de acesso não recebido', resposta: authData } };
    }

    serproTokenCache.set(cacheKey, {
      accessToken,
      jwtToken,
      expiresAt: Date.now() + SERPRO_TOKEN_TTL_MS,
    });
  }

  // Se test_only, retorna a confirmação de autenticação + tokens decodificados
  if (test_only) {
    // Decodifica o JWT (access_token) para extrair o CNPJ do contratante
    let jwtPayload = null;
    let jwtTokenPayload = null;
    try {
      const parts = accessToken.split('.');
      if (parts.length === 3) {
        jwtPayload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      }
    } catch (e) {}
    try {
      const parts = jwtToken.split('.');
      if (parts.length === 3) {
        jwtTokenPayload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      }
    } catch (e) {}

    return {
      status: 200,
      data: {
        success: true,
        message: 'Autenticação SERPRO realizada com sucesso',
        expires_in: 2008,
        token_type: 'Bearer',
        access_token_preview: accessToken.substring(0, 20) + '...',
        ambiente: ambiente || 'trial',
        // Tokens decodificados para descobrir o CNPJ do contratante
        access_token_decoded: jwtPayload,
        jwt_token_decoded: jwtTokenPayload,
      }
    };
  }

  // ── Passo 2: Fazer chamada à API Integra Contador (mTLS) ──
  if (!serproPath) {
    return { status: 400, data: { error: 'path é obrigatório (Apoiar, Consultar, Declarar, Emitir, Monitorar)' } };
  }

  const basePath = ambiente === 'producao'
    ? '/integra-contador/v1/'
    : '/integra-contador-trial/v1/';

  const apiRes = await mTlsRequestPfx({
    hostname: 'gateway.apiserpro.serpro.gov.br',
    path: basePath + serproPath,
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'jwt_token': jwtToken,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: serproBody ? JSON.stringify(serproBody) : undefined,
    pfx: pfxBuffer,
    passphrase: cert_senha,
  });

  let responseData;
  try { responseData = JSON.parse(apiRes.body); } catch { responseData = apiRes.body; }

  return { status: apiRes.status, data: responseData };
}

// ═══════════════════════ SERVIDOR HTTP ═══════════════════════

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── Normaliza o path (suporta proxy com path prefix, ex: /api/hotmart-proxy) ──
  let pathname = req.url || '/';
  try { pathname = new URL(req.url, 'http://localhost').pathname; } catch {}
  // remove possíveis prefixos comuns antes da rota
  const stripPrefix = (p) => {
    for (const prefix of ['/cora-proxy', '/hotmart-proxy', '/serpro-proxy', '/health']) {
      if (p === prefix || p === prefix + '/') return prefix;
      if (p.endsWith(prefix)) return prefix;
    }
    return p;
  };
  const route = stripPrefix(pathname);

  // Health check
  if (route === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      service: 'cora-mtls-proxy',
      version: '3.1.0',
      endpoints: ['/cora-proxy', '/hotmart-proxy', '/serpro-proxy'],
      node_options: process.env.NODE_OPTIONS || '(não definido)',
      openssl_legacy_provider: (process.env.NODE_OPTIONS || '').includes('openssl-legacy-provider'),
    }));
    return;
  }

  // ── Hotmart proxy ──
  if (route === '/hotmart-proxy' && req.method === 'POST') {
    const authHeader = req.headers.authorization;
    if (authHeader !== `Bearer ${HOTMART_PROXY_API_KEY}`) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized — API key inválida' }));
      return;
    }
    let bodyStr = '';
    for await (const chunk of req) bodyStr += chunk;
    try {
      const payload = JSON.parse(bodyStr);
      const result = await handleHotmartProxy(payload);
      res.writeHead(result.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.data));
    } catch (error) {
      console.error('[hotmart-proxy] Erro:', error.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  // ── SERPRO proxy ──
  if (route === '/serpro-proxy' && req.method === 'POST') {
    const authHeader = req.headers.authorization;
    if (authHeader !== `Bearer ${PROXY_API_KEY}`) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized — API key inválida' }));
      return;
    }
    let bodyStr = '';
    for await (const chunk of req) bodyStr += chunk;
    try {
      const payload = JSON.parse(bodyStr);
      const result = await handleSerproProxy(payload);
      res.writeHead(result.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.data));
    } catch (error) {
      console.error('[serpro-proxy] Erro:', error.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  // Endpoint principal (Cora)
  if (route === '/cora-proxy' && req.method === 'POST') {
    // Validar API key
    const authHeader = req.headers.authorization;
    if (authHeader !== `Bearer ${PROXY_API_KEY}`) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized — API key inválida' }));
      return;
    }

    // Ler body
    let bodyStr = '';
    for await (const chunk of req) bodyStr += chunk;

    try {
      const payload = JSON.parse(bodyStr);
      const result = await handleCoraProxy(payload);
      res.writeHead(result.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.data));
    } catch (error) {
      console.error('[cora-proxy] Erro:', error.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'PROXY_ROUTE_NOT_FOUND', received_path: pathname, method: req.method, endpoints: ['/cora-proxy (POST)', '/hotmart-proxy (POST)', '/serpro-proxy (POST)', '/health (GET)'], hint: 'Se você acabou de implantar uma nova rota, aguarde o redeploy concluir e tente novamente.' }));
});

server.listen(PORT, () => {
  console.log(`[proxy] Servidor rodando na porta ${PORT}`);
  console.log(`[proxy] Cora API Key: ${PROXY_API_KEY.substring(0, 4)}...`);
  console.log(`[proxy] Hotmart API Key: ${HOTMART_PROXY_API_KEY.substring(0, 4)}...`);
});