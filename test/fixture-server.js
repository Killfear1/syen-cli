'use strict';
const http = require('node:http');
const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  if (req.url === '/api/v1/meta') return res.end(JSON.stringify({ name: 'SYEN Comply', category: 'c', vendor: { name: 'SYEN Systems LLC', location: 'Brooklyn, NY, US' }, verification: { signature: 'ed25519', chaining: 'SHA-256 hash chain per tenant', anchoring: 'RFC 3161' }, pricing: [{ plan: 'Pro', price_usd_monthly: 33000, includes: 'Agent core' }], links: { demo: 'd', openapi: 'o' } }));
  if (req.url === '/api/v1/news') return res.end(JSON.stringify({ items: [{ title: 't', source: 'Reuters', url: null, framing: 'f', bucket: 'b' }] }));
  res.statusCode = 404; res.end('{}');
});
server.listen(0, '127.0.0.1', () => console.log(server.address().port));
