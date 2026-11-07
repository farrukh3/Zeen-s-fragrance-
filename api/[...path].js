const crypto = require('crypto');
const db = require('../lib/db');
const L = require('../lib/logic');

const PASSWORD = () => process.env.ADMIN_PASSWORD || '';
const SECRET = () =>
  crypto.createHash('sha256').update('zeen|' + PASSWORD() + '|' + (process.env.AUTH_SECRET || '')).digest();

// ---------- auth ----------
function sign(payload) {
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', SECRET()).update(p).digest('base64url');
  return p + '.' + s;
}
function verify(tok) {
  if (!tok || !PASSWORD()) return false;
  const [p, s] = String(tok).split('.');
  if (!p || !s) return false;
  const good = crypto.createHmac('sha256', SECRET()).update(p).digest('base64url');
  const a = Buffer.from(s), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
function cookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
const isAdmin = (req) => verify(cookie(req, 'zt'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- data helpers ----------
async function getSettings() {
  const s = (await db.get('settings')) || {};
  return { ...L.DEFAULT_SETTINGS, ...s, globalDiscount: { ...L.DEFAULT_SETTINGS.globalDiscount, ...(s.globalDiscount || {}) } };
}
async function getProducts() {
  let p = await db.get('products');
  if (!p) { p = L.SAMPLE_PRODUCTS(); await db.set('products', p); }
  return p;
}
const getOrders = async () => (await db.get('orders')) || [];
const getCoupons = async () => (await db.get('coupons')) || [];

async function readBody(req) {
  if (req.body !== undefined && req.body !== null && req.body !== '') {
    return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString();
  return raw ? JSON.parse(raw) : {};
}

function str(v, n) { return String(v == null ? '' : v).trim().slice(0, n); }

async function nextOrderId() {
  const n = await db.incr('order_counter');
  return { no: n, id: 'ZF-' + String(1000 + n) };
}

// ---------- router ----------
module.exports = async (req, res) => {
  const send = (status, data, headers = {}) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    for (const k in headers) res.setHeader(k, headers[k]);
    res.end(JSON.stringify(data));
  };
  try {
    const url = new URL(req.url, 'http://x');
    const parts = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method;
    const [a, b, c] = parts;

    // ===== public =====
    if (method === 'GET' && a === 'shop') {
      const [settings, products] = await Promise.all([getSettings(), getProducts()]);
      return send(200, { settings, products: products.filter((p) => p.active).map((p) => L.publicProduct(p, settings)) });
    }

    if (method === 'GET' && a === 'img' && b) {
      const d = await db.get('img:' + b);
      if (!d) { res.statusCode = 404; return res.end('Not found'); }
      const m = /^data:(image\/[\w+.-]+);base64,(.+)$/.exec(d);
      if (!m) { res.statusCode = 404; return res.end('Bad image'); }
      res.statusCode = 200;
      res.setHeader('Content-Type', m[1]);
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      return res.end(Buffer.from(m[2], 'base64'));
    }

    if (method === 'POST' && a === 'coupon') {
      const body = await readBody(req);
      const code = str(body.code, 30).toUpperCase();
      const sub = L.num(body.subtotal);
      const cp = (await getCoupons()).find((x) => x.code === code);
      if (!cp || !cp.active) return send(200, { ok: false, message: 'Coupon galat hai' });
      if (cp.expires && new Date(cp.expires + 'T23:59:59') < new Date()) return send(200, { ok: false, message: 'Coupon expire ho chuka hai' });
      if (sub < L.num(cp.minOrder)) return send(200, { ok: false, message: `Is coupon ke liye kam az kam Rs. ${cp.minOrder} ka order chahiye` });
      return send(200, { ok: true, code, discount: L.couponDiscount(cp, sub) });
    }

    if (method === 'POST' && a === 'order') {
      const body = await readBody(req);
      const cu = body.customer || {};
      const customer = { name: str(cu.name, 80), phone: str(cu.phone, 20), city: str(cu.city, 50), address: str(cu.address, 300), note: str(cu.note, 300) };
      if (!customer.name || !customer.phone || !customer.address || !customer.city)
        return send(400, { error: 'Naam, phone, city aur address zaroori hain' });
      if (!/^[+\d][\d\s-]{6,18}$/.test(customer.phone)) return send(400, { error: 'Phone number sahi likhein' });
      const [settings, products, coupons] = await Promise.all([getSettings(), getProducts(), getCoupons()]);
      const lines = L.buildLines(body.items, products, settings, { onlyActive: true });
      const coupon = coupons.find((x) => x.code === str(body.coupon, 30).toUpperCase());
      const t = L.totals(lines, settings, coupon);
      L.applyStock(products, lines, -1);
      const { no, id } = await nextOrderId();
      const order = {
        id, no, createdAt: new Date().toISOString(), source: 'online', status: 'pending', payment: 'COD',
        customer, lines, ...t, coupon: coupon && t.discount ? coupon.code : '',
      };
      await db.set('products', products);
      const orders = await getOrders();
      orders.unshift(order);
      await db.set('orders', orders);
      return send(200, { ok: true, order });
    }

    // ===== admin login =====
    if (a === 'admin' && b === 'login' && method === 'POST') {
      const body = await readBody(req);
      if (!PASSWORD()) return send(500, { error: 'ADMIN_PASSWORD Vercel environment variables mein set nahi hai' });
      const ok = (() => {
        const x = crypto.createHash('sha256').update(String(body.password || '')).digest();
        const y = crypto.createHash('sha256').update(PASSWORD()).digest();
        return crypto.timingSafeEqual(x, y);
      })();
      if (!ok) { await sleep(800); return send(401, { error: 'Password galat hai' }); }
      const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
      const tok = sign({ exp: Date.now() + 7 * 864e5 });
      return send(200, { ok: true }, { 'Set-Cookie': `zt=${tok}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800${secure}` });
    }
    if (a === 'admin' && b === 'logout') {
      return send(200, { ok: true }, { 'Set-Cookie': 'zt=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0' });
    }

    // ===== admin (protected) =====
    if (a === 'admin') {
      if (!isAdmin(req)) return send(401, { error: 'Login zaroori hai' });

      if (method === 'GET' && b === 'data') {
        const [settings, products, orders, coupons] = await Promise.all([getSettings(), getProducts(), getOrders(), getCoupons()]);
        return send(200, { settings, products, orders, coupons });
      }

      if (method === 'POST' && b === 'image') {
        const body = await readBody(req);
        const d = String(body.dataUrl || '');
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(d)) return send(400, { error: 'Sirf JPG/PNG/WEBP image' });
        if (d.length > 900000) return send(400, { error: 'Image bohat bari hai' });
        const id = crypto.randomBytes(8).toString('hex');
        await db.set('img:' + id, d);
        return send(200, { id });
      }

      if (method === 'POST' && b === 'product') {
        const body = await readBody(req);
        const products = await getProducts();
        const i = products.findIndex((p) => p.id === body.id);
        const old = i >= 0 ? products[i] : null;
        const np = L.cleanProduct(body, old);
        if (old) {
          for (const im of old.images) if (!np.images.includes(im)) await db.del('img:' + im);
          products[i] = np;
        } else products.unshift(np);
        await db.set('products', products);
        return send(200, { ok: true, product: np });
      }

      if (method === 'DELETE' && b === 'product' && c) {
        const products = await getProducts();
        const p = products.find((x) => x.id === c);
        if (p) for (const im of p.images) await db.del('img:' + im);
        await db.set('products', products.filter((x) => x.id !== c));
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'order' && c) {
        const body = await readBody(req);
        const status = str(body.status, 20);
        if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) return send(400, { error: 'Invalid status' });
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status === 'cancelled') return send(400, { error: 'Cancelled order dobara change nahi ho sakta' });
        if (status === 'cancelled') {
          const products = await getProducts();
          L.applyStock(products, o.lines, +1);
          await db.set('products', products);
        }
        o.status = status;
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      // in-store sale (POS)
      if (method === 'POST' && b === 'sale') {
        const body = await readBody(req);
        const [settings, products] = await Promise.all([getSettings(), getProducts()]);
        const lines = L.buildLines(body.items, products, settings, { onlyActive: false });
        const t = L.totals(lines, settings, null, body.discount, true);
        L.applyStock(products, lines, -1);
        const { no, id } = await nextOrderId();
        const order = {
          id, no, createdAt: new Date().toISOString(), source: 'store', status: 'delivered',
          payment: ['Cash', 'Card', 'Bank Transfer', 'JazzCash/Easypaisa'].includes(body.payment) ? body.payment : 'Cash',
          customer: { name: str(body.customerName, 80) || 'Walk-in', phone: str(body.customerPhone, 20), city: '', address: '', note: '' },
          lines, ...t, coupon: '',
        };
        await db.set('products', products);
        const orders = await getOrders();
        orders.unshift(order);
        await db.set('orders', orders);
        return send(200, { ok: true, order });
      }

      if (method === 'POST' && b === 'settings') {
        const body = await readBody(req);
        const cur = await getSettings();
        const g = body.globalDiscount || {};
        const next = {
          ...cur,
          shopName: str(body.shopName, 60) || cur.shopName,
          tagline: str(body.tagline, 120), heroTitle: str(body.heroTitle, 80), heroSub: str(body.heroSub, 200),
          announcement: str(body.announcement, 160),
          whatsapp: str(body.whatsapp, 20).replace(/\D/g, ''),
          phone: str(body.phone, 30), address: str(body.address, 200), instagram: str(body.instagram, 100),
          deliveryCharge: Math.max(0, Math.round(L.num(body.deliveryCharge))),
          freeDeliveryAbove: Math.max(0, Math.round(L.num(body.freeDeliveryAbove))),
          globalDiscount: { pct: L.clamp(Math.round(L.num(g.pct)), 0, 90), label: str(g.label, 60) },
        };
        await db.set('settings', next);
        return send(200, { ok: true, settings: next });
      }

      if (method === 'POST' && b === 'coupon') {
        const body = await readBody(req);
        const code = str(body.code, 30).toUpperCase().replace(/[^A-Z0-9_-]/g, '');
        if (!code) return send(400, { error: 'Coupon code likhein' });
        const cp = {
          code, type: body.type === 'fixed' ? 'fixed' : 'percent', value: Math.max(0, Math.round(L.num(body.value))),
          minOrder: Math.max(0, Math.round(L.num(body.minOrder))), expires: /^\d{4}-\d{2}-\d{2}$/.test(body.expires || '') ? body.expires : '',
          active: body.active !== false,
        };
        if (cp.type === 'percent') cp.value = Math.min(cp.value, 90);
        const list = await getCoupons();
        const i = list.findIndex((x) => x.code === code);
        if (i >= 0) list[i] = cp; else list.push(cp);
        await db.set('coupons', list);
        return send(200, { ok: true });
      }
      if (method === 'DELETE' && b === 'coupon' && c) {
        await db.set('coupons', (await getCoupons()).filter((x) => x.code !== c));
        return send(200, { ok: true });
      }
    }

    return send(404, { error: 'Not found' });
  } catch (e) {
    if (e instanceof SyntaxError) return send(400, { error: 'Bad request' });
    if (!e.status) console.error(e);
    return send(e.status || 500, { error: e.status ? e.message : 'Server error: ' + e.message });
  }
};
