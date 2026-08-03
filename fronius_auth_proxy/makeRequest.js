const http = require('http');
const crypto = require('crypto');
const { log } = require('./logger');

const sha256 = (str) => crypto.createHash('sha256').update(str).digest('hex');

const parseWWWAuthenticate = (header) => {
  const params = {};
  header.replace(/(\w+)="([^"]+)"/g, (_, k, v) => { params[k] = v; });
  return params;
};

const buildDigestAuth = (method, uri, wwwAuth, username, password, nc = '00000001') => {
  const { realm, nonce, qop, algorithm } = parseWWWAuthenticate(wwwAuth);
  const cnonce = crypto.randomBytes(8).toString('hex');
  const uriForHash = uri.split('?')[0];

  const ha1 = sha256(`${username}:${realm}:${password}`);
  const ha2 = sha256(`${method.toUpperCase()}:${uriForHash}`);
  const response = sha256(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);

  return `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uriForHash}", algorithm=${algorithm}, response="${response}", qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
};

const httpRequest = (options, body) => new Promise((resolve, reject) => {
  const req = http.request(options, res => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
  });
  req.on('error', reject);
  if (body) req.write(body);
  req.end();
});

const makeRequest = async ({ options, username, password, body }) => {
  log('Connecting to:', options.hostname, options.port);

  // Step 1: Get digest challenge from login endpoint
  const loginPath = `/api/commands/Login?user=${username}`;
  const loginOptions = {
    hostname: options.hostname,
    port: options.port,
    path: loginPath,
    method: 'GET',
  };

  const loginChallenge = await httpRequest(loginOptions);
  const loginWwwAuth = loginChallenge.headers['x-www-authenticate'] || loginChallenge.headers['www-authenticate'];
  log('Login challenge status:', loginChallenge.statusCode);

  if (!loginWwwAuth) {
    throw new Error('No auth challenge received from login endpoint');
  }

  // Step 2: Login with digest auth (nc=00000001)
  const loginAuth = buildDigestAuth('GET', loginPath, loginWwwAuth, username, password, '00000001');
  const loginResult = await httpRequest({
    ...loginOptions,
    headers: { 'Authorization': loginAuth },
  });
  log('Login result:', loginResult.statusCode);

  if (loginResult.statusCode !== 200) {
    throw new Error(`Login failed with status ${loginResult.statusCode}`);
  }

  // Step 3: Reuse same nonce for config request (nc=00000002)
  // The inverter accepts the same nonce for subsequent requests in the same session
  const configAuth = buildDigestAuth(options.method, options.path, loginWwwAuth, username, password, '00000002');
  log('Config auth computed');

  const authOptions = {
    ...options,
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      'Authorization': configAuth,
      ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
    },
  };

  const result = await httpRequest(authOptions, body);
  log('Response:', result.statusCode, result.body);
  return result;
};

module.exports = { makeRequest };
