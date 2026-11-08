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
  if (!tok || !PASSWORD()) return null;
  const [p, s] = String(tok).split('.');
  if (!p || !s) return null;
  const good = crypto.createHmac('sha256', SECRET()).update(p).digest('base64url');
  const a = Buffer.from(s), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}
function cookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
const PERMS = ['dash', 'sell', 'prod', 'ord', 'req', 'hist', 'rev', 'acc', 'off', 'set'];
// owner (ADMIN_PASSWORD) can do everything; staff accounts only what the owner ticked
async function getAuth(req) {
  const p = verify(cookie(req, 'zt'));
  if (!p) return null;
  if (!p.u || p.u === 'owner') return { owner: true, name: 'Owner', perms: new Set(PERMS) };
  const st = (await getStaff()).find((x) => x.id === p.u && x.active);
  if (!st) return null;
  return { owner: false, id: st.id, name: st.name, perms: new Set((st.perms || []).filter((x) => PERMS.includes(x))) };
}
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
const pwOk = (st, pw) => {
  const a = Buffer.from(hashPw(pw, st.salt), 'hex'), b = Buffer.from(st.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- data helpers ----------
async function getSettings() {
  const s = (await db.get('settings')) || {};
  return {
    ...L.DEFAULT_SETTINGS, ...s,
    globalDiscount: { ...L.DEFAULT_SETTINGS.globalDiscount, ...(s.globalDiscount || {}) },
    theme: { ...L.DEFAULT_SETTINGS.theme, ...(s.theme || {}) },
    payments: Object.fromEntries(Object.keys(L.DEFAULT_SETTINGS.payments).map((k) => [k, { ...L.DEFAULT_SETTINGS.payments[k], ...((s.payments || {})[k] || {}) }])),
  };
}
async function getProducts() {
  let p = await db.get('products');
  if (!p) { p = L.SAMPLE_PRODUCTS(); await db.set('products', p); }
  return p;
}
const getOrders = async () => (await db.get('orders')) || [];
const getCoupons = async () => (await db.get('coupons')) || [];
const getExpenses = async () => (await db.get('expenses')) || [];
const getRequests = async () => (await db.get('requests')) || [];
const getStaff = async () => (await db.get('staff')) || [];
const getReviews = async () => (await db.get('reviews')) || [];
const newToken = () => crypto.randomBytes(8).toString('hex');

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
    const raw = url.searchParams.has('path') ? url.searchParams.get('path') : url.pathname.replace(/^\/api\/?/, '');
    const parts = raw.split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method;
    const [a, b, c] = parts;

    // ===== public =====
    if (method === 'GET' && a === 'shop') {
      const [settings, products, reviews] = await Promise.all([getSettings(), getProducts(), getReviews()]);
      const rv = reviews.filter((r) => r.status === 'approved').sort((x, y) => (y.createdAt || '').localeCompare(x.createdAt || '')).slice(0, 40)
        .map(({ id, name, rating, text, source, createdAt }) => ({ id, name, rating, text, source, createdAt }));
      return send(200, { settings, products: products.filter((p) => p.active).map((p) => L.publicProduct(p, settings)), reviews: rv });
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
      const pm = (body.payment && body.payment.method) || 'cod';
      const PAYL = { cod: 'COD', bank: 'Bank Transfer', easypaisa: 'Easypaisa', jazzcash: 'JazzCash' };
      const pcfg = settings.payments[pm];
      if (!PAYL[pm] || !pcfg || (pm === 'cod' ? pcfg.enabled === false : !(pcfg.enabled && pcfg.number)))
        return send(400, { error: 'Yeh payment method abhi available nahi hai' });
      const lines = L.buildLines(body.items, products, settings, { onlyActive: true });
      const coupon = coupons.find((x) => x.code === str(body.coupon, 30).toUpperCase());
      const t = L.totals(lines, settings, coupon);
      L.applyStock(products, lines, -1);
      const { no, id } = await nextOrderId();
      const order = {
        id, no, token: newToken(), createdAt: new Date().toISOString(), source: 'online', status: 'pending', payment: PAYL[pm],
        paymentRef: pm === 'cod' ? '' : str(body.payment.ref, 60), paid: false,
        deliveryNote: settings.deliveryMode === 'fixed' ? '' : settings.deliveryNote,
        dcSet: settings.deliveryMode === 'fixed',
        customer, lines, ...t, coupon: coupon && t.discount ? coupon.code : '',
      };
      await db.set('products', products);
      const orders = await getOrders();
      orders.unshift(order);
      await db.set('orders', orders);
      return send(200, { ok: true, order: L.stripCost(order) });
    }

    // customer writes a review (waits for admin approval)
    if (method === 'POST' && a === 'review') {
      const body = await readBody(req);
      if (body.website) return send(200, { ok: true }); // honeypot
      const name = str(body.name, 60), text = str(body.text, 400), rating = L.clamp(Math.round(L.num(body.rating, 5)), 1, 5);
      if (!name || text.length < 5) return send(400, { error: 'Naam aur review likhein (kam az kam 5 huroof)' });
      const list = await getReviews();
      if (list.filter((r) => r.status === 'pending').length >= 60) return send(429, { error: 'Abhi bohat reviews pending hain, baad mein try karein' });
      if (!list.some((r) => r.name === name && r.text === text))
        list.unshift({ id: 'v_' + crypto.randomBytes(5).toString('hex'), name, rating, text, source: 'website', status: 'pending', createdAt: new Date().toISOString() });
      await db.set('reviews', list.slice(0, 500));
      return send(200, { ok: true });
    }

    // customer asks for an out-of-stock perfume
    if (method === 'POST' && a === 'request') {
      const body = await readBody(req);
      const name = str(body.name, 80), phone = str(body.phone, 20);
      if (!name || !/^[+\d][\d\s-]{6,18}$/.test(phone)) return send(400, { error: 'Naam aur sahi phone number likhein' });
      const products = await getProducts();
      const p = products.find((x) => x.id === body.pid && x.active);
      const v = p && p.variants.find((x) => x.size === body.size);
      if (!p || !v) return send(400, { error: 'Product nahi mila' });
      const list = await getRequests();
      const dig = phone.replace(/\D/g, '');
      const dup = list.find((r) => r.status === 'open' && r.pid === p.id && r.size === v.size && r.phone.replace(/\D/g, '') === dig);
      if (!dup) {
        list.unshift({ id: 'r_' + crypto.randomBytes(5).toString('hex'), pid: p.id, pname: p.name, size: v.size, name, phone,
          qty: L.clamp(Math.round(L.num(body.qty, 1)), 1, 20), note: str(body.note, 200), createdAt: new Date().toISOString(), status: 'open' });
        await db.set('requests', list.slice(0, 500));
      }
      return send(200, { ok: true });
    }

    // public invoice (needs the secret token from the invoice link, or admin login)
    if (method === 'GET' && a === 'invoice' && b) {
      const o = (await getOrders()).find((x) => x.id === b);
      const t = url.searchParams.get('t') || '';
      const au = await getAuth(req);
      const admin = !!au;
      const tokOk = !!(o && o.token && t.length === o.token.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(o.token)));
      if (!o || !(admin || tokOk)) return send(404, { error: 'Invoice nahi mila' });
      if (o.source !== 'store' && o.dcSet === false) return send(409, { error: 'Delivery charges abhi set nahi hue. Thori der baad try karein.' });
      const st = await getSettings();
      const shop = { shopName: st.shopName, logo: st.logo, address: st.address, phone: st.phone, whatsapp: st.whatsapp, instagram: st.instagram, facebook: st.facebook, invoiceNote: st.invoiceNote, invoiceTerms: st.invoiceTerms, deliveryDays: st.deliveryDays, accent: st.theme.accent };
      return send(200, { order: au && au.perms.has('acc') ? o : L.stripCost(o), shop });
    }

    // ===== admin login =====
    if (a === 'admin' && b === 'login' && method === 'POST') {
      const body = await readBody(req);
      if (!PASSWORD()) return send(500, { error: 'ADMIN_PASSWORD Vercel environment variables mein set nahi hai' });
      const uname = str(body.username, 30).toLowerCase();
      let uid = null;
      if (!uname || uname === 'admin') {
        const x = crypto.createHash('sha256').update(String(body.password || '')).digest();
        const y = crypto.createHash('sha256').update(PASSWORD()).digest();
        if (crypto.timingSafeEqual(x, y)) uid = 'owner';
      } else {
        const st = (await getStaff()).find((z) => z.username === uname && z.active);
        if (st && pwOk(st, body.password || '')) uid = st.id;
      }
      if (!uid) { await sleep(800); return send(401, { error: 'Username ya password galat hai' }); }
      const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
      const tok = sign({ exp: Date.now() + 7 * 864e5, u: uid });
      return send(200, { ok: true }, { 'Set-Cookie': `zt=${tok}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800${secure}` });
    }
    if (a === 'admin' && b === 'logout') {
      return send(200, { ok: true }, { 'Set-Cookie': 'zt=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0' });
    }

    // ===== admin (protected) =====
    if (a === 'admin') {
      const au = await getAuth(req);
      if (!au) return send(401, { error: 'Login zaroori hai' });
      const need = (p) => { if (!au.perms.has(p)) throw L.httpErr(403, 'Is kaam ki ijazat nahi hai'); };

      if (method === 'GET' && b === 'data') {
        const [settings, products0, orders0, coupons, expenses0, requests, reviews, staff] = await Promise.all([getSettings(), getProducts(), getOrders(), getCoupons(), getExpenses(), getRequests(), getReviews(), getStaff()]);
        let products = products0, orders = orders0;
        let changed = false;
        for (const o of orders) if (!o.token) { o.token = newToken(); changed = true; }
        if (changed) await db.set('orders', orders);
        const seeCost = au.perms.has('acc');
        if (!seeCost) {
          products = products.map((p) => ({ ...p, variants: p.variants.map(({ cost, ...v }) => v) }));
          orders = orders.map(L.stripCost);
        }
        return send(200, {
          settings, products, orders, coupons, expenses: seeCost ? expenses0 : [], requests, reviews: au.perms.has('rev') ? reviews : [],
          staff: au.owner ? staff.map(({ salt, hash, ...x }) => x) : [],
          me: { owner: au.owner, name: au.name, perms: [...au.perms] },
        });
      }

      if (method === 'POST' && b === 'image') {
        if (!au.perms.has('prod') && !au.perms.has('set')) need('prod');
        const body = await readBody(req);
        const d = String(body.dataUrl || '');
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(d)) return send(400, { error: 'Sirf JPG/PNG/WEBP image' });
        if (d.length > 900000) return send(400, { error: 'Image bohat bari hai' });
        const id = crypto.randomBytes(8).toString('hex');
        await db.set('img:' + id, d);
        return send(200, { id });
      }

      if (method === 'POST' && b === 'product') {
        need('prod');
        const body = await readBody(req);
        const products = await getProducts();
        const i = products.findIndex((p) => p.id === body.id);
        const old = i >= 0 ? products[i] : null;
        const np = L.cleanProduct(body, old);
        if (!au.perms.has('acc')) for (const v of np.variants) { const ov = old && old.variants.find((x) => x.size === v.size); v.cost = ov ? ov.cost : 0; } // staff cannot see/change cost
        if (old) {
          for (const im of old.images) if (!np.images.includes(im)) await db.del('img:' + im);
          products[i] = np;
        } else products.unshift(np);
        await db.set('products', products);
        return send(200, { ok: true, product: np });
      }

      if (method === 'DELETE' && b === 'product' && c) {
        need('prod');
        const products = await getProducts();
        const p = products.find((x) => x.id === c);
        if (p) for (const im of p.images) await db.del('img:' + im);
        await db.set('products', products.filter((x) => x.id !== c));
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'order' && c && parts[3] === 'dc') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status === 'cancelled') return send(400, { error: 'Cancelled order mein DC set nahi ho sakta' });
        const amt = L.clamp(Math.round(L.num(body.amount)), 0, 5000);
        o.delivery = amt;
        o.total = o.subtotal - o.discount + amt;
        o.dcSet = true;
        await db.set('orders', orders);
        return send(200, { ok: true, order: au.perms.has('acc') ? o : L.stripCost(o) });
      }

      if (b === 'request' && c) {
        need('req');
        const list = await getRequests();
        if (method === 'DELETE') { await db.set('requests', list.filter((x) => x.id !== c)); return send(200, { ok: true }); }
        if (method === 'POST') {
          const body = await readBody(req);
          const r = list.find((x) => x.id === c);
          if (!r) return send(404, { error: 'Request nahi mili' });
          r.status = body.status === 'done' ? 'done' : 'open';
          await db.set('requests', list);
          return send(200, { ok: true });
        }
      }

      if (method === 'POST' && b === 'order' && c && parts[3] === 'paid') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        o.paid = body.paid !== false;
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'order' && c) {
        need('ord');
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
        if (status === 'delivered' && o.payment === 'COD') o.paid = true;
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      // in-store sale (POS)
      if (method === 'POST' && b === 'sale') {
        need('sell');
        const body = await readBody(req);
        const [settings, products] = await Promise.all([getSettings(), getProducts()]);
        const lines = L.buildLines(body.items, products, settings, { onlyActive: false });
        const t = L.totals(lines, settings, null, body.discount, true);
        L.applyStock(products, lines, -1);
        const { no, id } = await nextOrderId();
        const order = {
          id, no, token: newToken(), createdAt: new Date().toISOString(), source: 'store', status: 'delivered', dcSet: true,
          payment: ['Cash', 'Card', 'Bank Transfer', 'Easypaisa', 'JazzCash'].includes(body.payment) ? body.payment : 'Cash', paid: true,
          customer: { name: str(body.customerName, 80) || 'Walk-in', phone: str(body.customerPhone, 20), city: '', address: '', note: '' },
          lines, ...t, coupon: '',
        };
        await db.set('products', products);
        const orders = await getOrders();
        orders.unshift(order);
        await db.set('orders', orders);
        return send(200, { ok: true, order: au.perms.has('acc') ? order : L.stripCost(order) });
      }

      if (method === 'POST' && b === 'settings') {
        need('set');
        const body = await readBody(req);
        const cur = await getSettings();
        const g = body.globalDiscount || {};
        const next = {
          ...cur,
          shopName: str(body.shopName, 60) || cur.shopName,
          tagline: str(body.tagline, 120), heroTitle: str(body.heroTitle, 80), heroSub: str(body.heroSub, 200),
          announcement: body.announcement === undefined ? cur.announcement : str(body.announcement, 200),
          whatsapp: str(body.whatsapp, 20).replace(/\D/g, ''),
          phone: str(body.phone, 30), address: str(body.address, 200), instagram: str(body.instagram, 150),
          deliveryCharge: Math.max(0, Math.round(L.num(body.deliveryCharge))),
          freeDeliveryAbove: Math.max(0, Math.round(L.num(body.freeDeliveryAbove))),
          globalDiscount: { pct: L.clamp(Math.round(L.num(g.pct)), 0, 90), label: str(g.label, 60) },
        };
        // design: theme colors, logo and hero image (kept as-is when not sent)
        const hex = (v, d) => (/^#[0-9a-fA-F]{6}$/.test(v || '') ? v : d);
        const imgId = (v, d) => (v === undefined ? d : /^[\w-]{4,40}$/.test(v || '') ? v : '');
        if (body.theme) {
          const t = body.theme, ct = cur.theme;
          next.theme = { bg: hex(t.bg, ct.bg), card: hex(t.card, ct.card), accent: hex(t.accent, ct.accent), ink: hex(t.ink, ct.ink) };
        }
        const hx = (v, d) => (v === undefined ? d : /^#[0-9a-fA-F]{6}$/.test(v || '') ? v : '');
        next.annEffect = body.annEffect === undefined ? cur.annEffect : ['static', 'slide', 'blink', 'slideblink'].includes(body.annEffect) ? body.annEffect : 'static';
        next.annSpeed = body.annSpeed === undefined ? cur.annSpeed : ['slow', 'normal', 'fast'].includes(body.annSpeed) ? body.annSpeed : 'normal';
        next.annBold = body.annBold === undefined ? !!cur.annBold : !!body.annBold;
        next.annColor = hx(body.annColor, cur.annColor);
        next.annBg = hx(body.annBg, cur.annBg);
        next.facebook = body.facebook === undefined ? cur.facebook : str(body.facebook, 150);
        next.deliveryMode = body.deliveryMode === undefined ? cur.deliveryMode : body.deliveryMode === 'fixed' ? 'fixed' : 'note';
        next.deliveryDays = body.deliveryDays === undefined ? cur.deliveryDays : str(body.deliveryDays, 40) || '7 working days';
        next.deliveryNote = body.deliveryNote === undefined ? cur.deliveryNote : str(body.deliveryNote, 220);
        if (body.payments) {
          const bp = body.payments;
          const acct = (k) => { const x = bp[k] || {}; const num = str(x.number, 60); return { enabled: !!x.enabled && !!num, bankName: str(x.bankName, 60), title: str(x.title, 60), number: num }; };
          next.payments = { cod: { enabled: !bp.cod || bp.cod.enabled !== false }, bank: acct('bank'), easypaisa: acct('easypaisa'), jazzcash: acct('jazzcash') };
          const P = next.payments;
          if (!P.cod.enabled && !P.bank.enabled && !P.easypaisa.enabled && !P.jazzcash.enabled) P.cod.enabled = true;
        } else next.payments = cur.payments;
        next.invoiceNote = body.invoiceNote === undefined ? cur.invoiceNote : str(body.invoiceNote, 300);
        next.invoiceTerms = body.invoiceTerms === undefined ? cur.invoiceTerms : str(body.invoiceTerms, 400);
        next.logo = imgId(body.logo, cur.logo);
        next.heroImage = imgId(body.heroImage, cur.heroImage);
        for (const k of ['logo', 'heroImage']) if (cur[k] && cur[k] !== next[k]) await db.del('img:' + cur[k]);
        await db.set('settings', next);
        return send(200, { ok: true, settings: next });
      }

      if (method === 'POST' && b === 'expense') {
        need('acc');
        const body = await readBody(req);
        const amount = Math.round(L.num(body.amount));
        if (amount <= 0) return send(400, { error: 'Amount likhein' });
        const ex = {
          id: /^e_\w{4,20}$/.test(body.id || '') ? body.id : 'e_' + crypto.randomBytes(5).toString('hex'),
          date: /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : new Date().toISOString().slice(0, 10),
          category: str(body.category, 40) || 'Other', note: str(body.note, 120), amount,
        };
        const list = await getExpenses();
        const i = list.findIndex((x) => x.id === ex.id);
        if (i >= 0) list[i] = ex; else list.unshift(ex);
        await db.set('expenses', list);
        return send(200, { ok: true });
      }
      if (method === 'DELETE' && b === 'expense' && c) {
        need('acc');
        await db.set('expenses', (await getExpenses()).filter((x) => x.id !== c));
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'coupon') {
        need('off');
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
        need('off');
        await db.set('coupons', (await getCoupons()).filter((x) => x.code !== c));
        return send(200, { ok: true });
      }

      // ----- reviews (add from Facebook, approve customer reviews) -----
      if (b === 'review') {
        need('rev');
        const list = await getReviews();
        if (method === 'POST' && !c) {
          const body = await readBody(req);
          const name = str(body.name, 60), text = str(body.text, 400);
          if (!name || !text) return send(400, { error: 'Naam aur review likhein' });
          const src = ['facebook', 'website', 'instagram', 'whatsapp'].includes(body.source) ? body.source : 'facebook';
          const when = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? new Date(body.date + 'T12:00:00').toISOString() : new Date().toISOString();
          list.unshift({ id: 'v_' + crypto.randomBytes(5).toString('hex'), name, rating: L.clamp(Math.round(L.num(body.rating, 5)), 1, 5), text, source: src, status: 'approved', createdAt: when });
          await db.set('reviews', list.slice(0, 500));
          return send(200, { ok: true });
        }
        if (method === 'POST' && c) {
          const body = await readBody(req);
          const r = list.find((x) => x.id === c);
          if (!r) return send(404, { error: 'Review nahi mila' });
          r.status = ['approved', 'hidden', 'pending'].includes(body.status) ? body.status : r.status;
          await db.set('reviews', list);
          return send(200, { ok: true });
        }
        if (method === 'DELETE' && c) { await db.set('reviews', list.filter((x) => x.id !== c)); return send(200, { ok: true }); }
      }

      // ----- staff accounts (owner only) -----
      if (b === 'staff') {
        if (!au.owner) throw L.httpErr(403, 'Sirf owner staff manage kar sakta hai');
        const list = await getStaff();
        if (method === 'DELETE' && c) { await db.set('staff', list.filter((x) => x.id !== c)); return send(200, { ok: true }); }
        if (method === 'POST') {
          const body = await readBody(req);
          const name = str(body.name, 60), username = str(body.username, 20).toLowerCase();
          if (!name) return send(400, { error: 'Staff ka naam likhein' });
          if (!/^[a-z0-9._-]{3,20}$/.test(username) || username === 'admin') return send(400, { error: 'Username 3-20 huroof/numbers ho (admin nahi ho sakta)' });
          const perms = (Array.isArray(body.perms) ? body.perms : []).filter((x) => PERMS.includes(x));
          const i = list.findIndex((x) => x.id === body.id);
          if (list.some((x, j) => x.username === username && j !== i)) return send(400, { error: 'Yeh username pehle se maujood hai' });
          const pw = String(body.password || '');
          if (i < 0 && pw.length < 6) return send(400, { error: 'Password kam az kam 6 huroof ka ho' });
          if (pw && pw.length < 6) return send(400, { error: 'Password kam az kam 6 huroof ka ho' });
          const old = i >= 0 ? list[i] : null;
          const salt = pw ? crypto.randomBytes(12).toString('hex') : old.salt;
          const st = { id: old ? old.id : 's_' + crypto.randomBytes(5).toString('hex'), name, username, perms, active: body.active !== false, salt, hash: pw ? hashPw(pw, salt) : old.hash, createdAt: old ? old.createdAt : new Date().toISOString() };
          if (i >= 0) list[i] = st; else list.push(st);
          await db.set('staff', list);
          return send(200, { ok: true });
        }
      }
    }

    return send(404, { error: 'Not found' });
  } catch (e) {
    if (e instanceof SyntaxError) return send(400, { error: 'Bad request' });
    if (!e.status) console.error(e);
    return send(e.status || 500, { error: e.status ? e.message : 'Server error: ' + e.message });
  }
};
