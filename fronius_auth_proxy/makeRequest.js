const http = require('http');
const crypto = require('crypto');
const { log } = require('./logger');

const sha256 = (str) => crypto.createHash('sha256').update(str).digest('hex');

const parseWWWAuthenticate = (header) => {
  const params = {};
  header.replace(/(\w+)="([^"]+)"/g, (_, k, v) => { params[k] = v; });
  return params;
};

const buildDigestAuth = (method, uri, wwwAuth, username, password) => {
  const { realm, nonce, qop, algorithm } = parseWWWAuthenticate(wwwAuth);
  const nc = '00000001';
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
  // Step 1: Login to establish session
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

  const loginAuth = buildDigestAuth('GET', loginPath, loginWwwAuth, username, password);
  const loginResult = await httpRequest({
    ...loginOptions,
    headers: { 'Authorization': loginAuth },
  });
  log('Login result:', loginResult.statusCode);

  if (loginResult.statusCode !== 200) {
    throw new Error(`Login failed with status ${loginResult.statusCode}`);
  }

  // Capture session cookie if set
  const cookie = loginResult.headers['set-cookie'];
  log('Session cookie:', cookie);

  // Step 2: Get digest challenge for the actual endpoint
  const challengeOptions = {
    ...options,
    headers: {
      ...(cookie ? { 'Cookie': Array.isArray(cookie) ? cookie.join('; ') : cookie } : {}),
    },
  };
  const challenge = await httpRequest(challengeOptions);
  log('Config challenge status:', challenge.statusCode);

  const wwwAuth = challenge.headers['x-www-authenticate'] || challenge.headers['www-authenticate'];

  let authOptions;
  if (wwwAuth) {
    // Normal digest flow
    const auth = buildDigestAuth(options.method, options.path, wwwAuth, username, password);
    log('Auth header computed:', auth);
    authOptions = {
      ...options,
      headers: {
        'Content-Type': 'application/json;charset=utf-8',
        'Authorization': auth,
        ...(cookie ? { 'Cookie': Array.isArray(cookie) ? cookie.join('; ') : cookie } : {}),
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };
  } else {
    // No challenge — try sending with session cookie only (already authenticated via login)
    log('No auth challenge for config endpoint, trying with session cookie only');
    authOptions = {
      ...options,
      headers: {
        'Content-Type': 'application/json;charset=utf-8',
        ...(cookie ? { 'Cookie': Array.isArray(cookie) ? cookie.join('; ') : cookie } : {}),
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };
  }

  const result = await httpRequest(authOptions, body);
  log('Response:', result.statusCode, result.body);
  return result;
};

module.exports = { makeRequest };
