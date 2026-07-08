const http = require('http');
const https = require('https');

const PROXY_API_KEY = process.env.PROXY_API_KEY || 'cora-proxy-change-this-key';
const PORT = process.env.PORT || 3001;

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
    req.setTimeout(30000, () => req.destroy(new Error('Timeout')));
    if (body) req.write(body);
    req.end();
  });
}

async function handleCoraProxy(payload) {
  const { client_id, cert_pem, private_key, ambiente, method, path: coraPath, body: coraBody, params, idempotency_key } = payload;
  if (!client_id || !cert_pem || !private_key) return { status: 400, data: { error: 'credenciais incompletas' } };
  if (!coraPath) return { status: 400, data: { error: 'path obrigatório' } };

  const hostname = ambiente === 'producao' ? 'matls-clients.api.cora.com.br' : 'matls-clients.api.stage.cora.com.br';

  const tokenRes = await mTlsRequest({
    hostname, path: '/token', method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials&client_id=' + client_id,
    cert: cert_pem, key: private_key,
  });
  if (tokenRes.status !== 200) return { status: 502, data: { error: 'Falha auth Cora', cora_status: tokenRes.status, cora_response: tokenRes.body } };

  const accessToken = JSON.parse(tokenRes.body).access_token;

  let fullPath = coraPath;
  if (params) {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) { if (v !== undefined && v !== null && v !== '') sp.set(k, String(v)); }
    const qs = sp.toString();
    if (qs) fullPath += '?' + qs;
  }

  const apiHeaders = { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' };
  if (idempotency_key) apiHeaders['Idempotency-Key'] = idempotency_key;

  let apiBodyStr;
  const upperMethod = (method || 'GET').toUpperCase();
  if (coraBody && upperMethod !== 'GET') {
    apiHeaders['Content-Type'] = 'application/json';
    apiBodyStr = JSON.stringify(coraBody);
  }

  const apiRes = await mTlsRequest({ hostname, path: fullPath, method: upperMethod, headers: apiHeaders, body: apiBodyStr, cert: cert_pem, key: private_key });

  let responseData;
  try { responseData = JSON.parse(apiRes.body); } catch { responseData = apiRes.body; }
  return { status: apiRes.status, data: responseData };
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  if (req.url === '/health') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true })); return; }
  if (req.url === '/cora-proxy' && req.method === 'POST') {
    if (req.headers.authorization !== `Bearer ${PROXY_API_KEY}`) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }
    let bodyStr = '';
    for await (const chunk of req) bodyStr += chunk;
    try {
      const result = await handleCoraProxy(JSON.parse(bodyStr));
      res.writeHead(result.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.data));
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => console.log(`Proxy rodando na porta ${PORT}`));
