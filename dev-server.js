// Local test server: node dev-server.js  (ADMIN_PASSWORD=xxx PORT=3000)
const http = require('http');
const fs = require('fs');
const path = require('path');
const handler = require('./api/[...path].js');
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg' };
http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return handler(req, res);
  let p = req.url.split('?')[0];
  if (p.endsWith('/')) p += 'index.html';
  if (p === '/admin') p = '/admin/index.html';
  const f = path.join(__dirname, 'public', p);
  if (!f.startsWith(path.join(__dirname, 'public')) || !fs.existsSync(f)) { res.statusCode = 404; return res.end('404'); }
  res.setHeader('Content-Type', types[path.extname(f)] || 'application/octet-stream');
  fs.createReadStream(f).pipe(res);
}).listen(process.env.PORT || 3000, () => console.log('http://localhost:' + (process.env.PORT || 3000)));
