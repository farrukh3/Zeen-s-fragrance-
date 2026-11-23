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
const getOwner = async () => (await db.get('owner')) || null;
const verOf = (h) => crypto.createHash('sha256').update('v|' + h).digest('hex').slice(0, 10);
const ownerVer = (rec) => verOf(rec ? rec.hash : 'env');
async function ownerOk(pw) {
  const rec = await getOwner();
  const x = crypto.createHash('sha256').update(String(pw || '')).digest();
  // ADMIN_PASSWORD from Vercel always works as the emergency/recovery password
  if (crypto.timingSafeEqual(x, crypto.createHash('sha256').update(PASSWORD()).digest())) return true;
  return !!(rec && pwOk(rec, pw || ''));
}
async function getAuth(req) {
  const p = verify(cookie(req, 'zt'));
  if (!p) return null;
  if (!p.u || p.u === 'owner') {
    if (p.v !== ownerVer(await getOwner())) return null;
    return { owner: true, name: 'Owner', perms: new Set(PERMS) };
  }
  const st = (await getStaff()).find((x) => x.id === p.u && x.active);
  if (!st || p.v !== verOf(st.hash)) return null;
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
const getDeals = async () => (await db.get('deals')) || [];
const dealLive = (d, now = Date.now()) => d.active !== false && now >= Date.parse(d.start) && now <= Date.parse(d.end);
const getExpenses = async () => (await db.get('expenses')) || [];
const getRequests = async () => (await db.get('requests')) || [];
const getStaff = async () => (await db.get('staff')) || [];
const getReviews = async () => (await db.get('reviews')) || [];
const newToken = () => crypto.randomBytes(8).toString('hex');

async function readBody(req, max = 300000) {
  if (+req.headers['content-length'] > max) throw L.httpErr(413, 'Data bohat bara hai');
  if (req.body !== undefined && req.body !== null && req.body !== '') {
    return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString();
  return raw ? JSON.parse(raw) : {};
}

// ---------- abuse protection ----------
const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'x').split(',')[0].trim().slice(0, 60);
async function limited(req, name, max, windowSec, extra = '') {
  try { return (await db.hit(`rl:${name}:${clientIp(req)}${extra}`, windowSec)) > max; } catch { return false; }
}
const TOO_MANY = { error: 'Bohat zyada koshishein. Thori der baad dobara try karein.' };

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
      const [settings, products, reviews, deals] = await Promise.all([getSettings(), getProducts(), getReviews(), getDeals()]);
      const nowMs = Date.now();
      const liveDeals = deals.filter((d) => dealLive(d, nowMs)).map(({ id, title, subtitle, items, price, start, end, image }) => ({ id, title, subtitle, items, price, start, end, image: image || '' }));
      const rv = reviews.filter((r) => r.status === 'approved').sort((x, y) => (y.createdAt || '').localeCompare(x.createdAt || '')).slice(0, 40)
        .map(({ id, name, rating, text, source, createdAt }) => ({ id, name, rating, text, source, createdAt }));
      return send(200, { settings, products: products.filter((p) => p.active).map((p) => L.publicProduct(p, settings)), reviews: rv, deals: liveDeals, now: nowMs });
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
      if (await limited(req, 'coupon', 40, 600)) return send(429, TOO_MANY);
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
      if (await limited(req, 'order', 20, 3600)) return send(429, TOO_MANY);
      const body = await readBody(req, 1300000);
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
      // online payment needs a transaction ID and a screenshot
      let ref = '', proof = '';
      if (pm !== 'cod') {
        ref = str(body.payment && body.payment.ref, 60).replace(/\s+/g, ' ');
        proof = String((body.payment && body.payment.proof) || '');
        if (ref.length < 4) return send(400, { error: 'Transaction ID likhna zaroori hai (kam az kam 4 huroof)' });
        if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(proof)) return send(400, { error: 'Payment ka screenshot lagana zaroori hai (JPG/PNG)' });
        if (proof.length > 1100000) return send(400, { error: 'Screenshot bohat bara hai, chhota screenshot lagayein' });
        const oldOrders = await getOrders();
        const refKey = ref.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (oldOrders.some((o) => o.status !== 'cancelled' && o.paymentRef && o.paymentRef.toLowerCase().replace(/[^a-z0-9]/g, '') === refKey))
          return send(400, { error: 'Yeh Transaction ID pehle kisi order mein use ho chuki hai. Sahi ID likhein.' });
      }
      // deal bundles in the cart are expanded into normal product lines, priced so that the bundle adds up to the deal price
      const deals = await getDeals();
      const flat = [], groups = [];
      for (const it of Array.isArray(body.items) ? body.items : []) {
        if (it && it.deal) {
          const d = deals.find((x) => x.id === String(it.deal));
          const n = L.clamp(Math.round(L.num(it.qty, 1)), 1, 10);
          if (!d || !dealLive(d)) return send(400, { error: 'Ek deal khatam ho chuki hai. Cart se hata kar dobara dekhein.' });
          groups.push({ d, n, start: flat.length });
          for (const di of d.items) flat.push({ pid: di.pid, size: di.size, qty: di.qty * n });
        } else flat.push(it);
      }
      const lines = L.buildLines(flat, products, settings, { onlyActive: true });
      for (const g of groups) {
        const seg = lines.slice(g.start, g.start + g.d.items.length);
        const per = seg.map((l, j) => l.unit * g.d.items[j].qty); // normal value of one bundle, line by line
        const S = per.reduce((a, x) => a + x, 0) || 1;
        let acc = 0;
        seg.forEach((l, j) => {
          const share = j === seg.length - 1 ? g.d.price - acc : Math.round((g.d.price * per[j]) / S);
          acc += share;
          l.total = share * g.n; l.unit = Math.round(l.total / l.qty); l.deal = g.d.title;
        });
      }
      if (lines.reduce((a, l) => a + l.qty, 0) > 30) return send(400, { error: 'Itne zyada perfume ke liye humein WhatsApp par message karein' });
      if (await limited(req, 'orderph', 4, 3600, ':' + customer.phone.replace(/\D/g, ''))) return send(429, TOO_MANY);
      const coupon = coupons.find((x) => x.code === str(body.coupon, 30).toUpperCase());
      const t = L.totals(lines, settings, coupon);
      L.applyStock(products, lines, -1);
      const { no, id } = await nextOrderId();
      const order = {
        id, no, token: newToken(), createdAt: new Date().toISOString(), source: 'online', status: 'pending', payment: PAYL[pm],
        paymentRef: ref, proof: !!proof, paid: false,
        deliveryNote: settings.deliveryMode === 'fixed' ? '' : settings.deliveryNote,
        dcSet: settings.deliveryMode === 'fixed',
        customer, lines, ...t, coupon: coupon && t.discount ? coupon.code : '',
      };
      await db.set('products', products);
      if (proof) await db.set('pay:' + id, proof);
      const orders = await getOrders();
      orders.unshift(order);
      await db.set('orders', orders);
      return send(200, { ok: true, order: L.stripCost(order) });
    }

    // customer writes a review (waits for admin approval)
    if (method === 'POST' && a === 'review') {
      if (await limited(req, 'review', 10, 3600)) return send(429, TOO_MANY);
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
      if (await limited(req, 'request', 10, 3600)) return send(429, TOO_MANY);
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
      if (await limited(req, 'invoice', 80, 600)) return send(429, TOO_MANY);
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
      if (await limited(req, 'login', 10, 600)) { await sleep(800); return send(429, { error: 'Bohat zyada galat koshishein. 10 minute baad try karein.' }); }
      const body = await readBody(req);
      if (!PASSWORD()) return send(500, { error: 'ADMIN_PASSWORD Vercel environment variables mein set nahi hai' });
      const uname = str(body.username, 30).toLowerCase();
      if (await limited(req, 'loginu', 30, 3600, ':' + (uname || 'owner'))) { await sleep(800); return send(429, { error: 'Is account par bohat koshishein hui hain. Thori der baad try karein.' }); }
      let uid = null;
      if (!uname || uname === 'admin') {
        if (await ownerOk(body.password)) uid = 'owner';
      } else {
        const st = (await getStaff()).find((z) => z.username === uname && z.active);
        if (st && pwOk(st, body.password || '')) uid = st.id;
      }
      if (!uid) { await sleep(800); return send(401, { error: 'Username ya password galat hai' }); }
      const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
      const ver = uid === 'owner' ? ownerVer(await getOwner()) : verOf((await getStaff()).find((z) => z.id === uid).hash);
      const tok = sign({ exp: Date.now() + 7 * 864e5, u: uid, v: ver });
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
      const NEED_SIZES = ['100ml', '50ml', '30ml', '10ml'];
      const normSize = (x) => String(x || '').toLowerCase().replace(/\s+/g, '');
      // keeps the auto "Customer orders (backorder)" requirement list in step with orders waiting for stock
      const needSync = async (pid, pname, size, delta) => {
        const sz = normSize(size);
        if (!NEED_SIZES.includes(sz) || !delta) return;
        const list = (await db.get('needs')) || [];
        let n = list.find((x) => x.auto && x.status === 'open');
        if (!n) {
          if (delta < 0) return;
          n = { id: 'n_' + crypto.randomBytes(5).toString('hex'), title: 'Customer orders (backorder)', status: 'open', createdAt: new Date().toISOString(), by: au.name, auto: true, lines: [] };
          list.unshift(n);
        }
        let l = n.lines.find((x) => x.pid === pid && x.size === sz && !x.tester);
        if (!l) {
          if (delta < 0) return;
          l = { id: 'l_' + crypto.randomBytes(4).toString('hex'), pid, pname, size: sz, qty: 0, tester: false };
          n.lines.push(l);
        }
        l.qty += delta;
        if (l.qty <= 0) n.lines = n.lines.filter((x) => x !== l);
        if (!n.lines.length) list.splice(list.indexOf(n), 1);
        await db.set('needs', list.slice(0, 60));
      };
      const backSync = async (lines, sign) => { for (const l of lines) if (l.back > 0) await needSync(l.pid, l.name, l.size, sign * l.back); };
      const payRep = (o) => (o.payments || []).reduce((a, x) => a + x.amount, 0);
      const dueOf = (o) => (o.udhaar && o.status !== 'cancelled' ? Math.max(0, o.total - payRep(o)) : 0);
      const custKey = (o) => {
        const cu = o.customer || {}, d = String(cu.phone || '').replace(/\D/g, '').slice(-10), nm = String(cu.name || '').toLowerCase().trim();
        return d.length >= 10 ? d : nm && nm !== 'walk-in' ? 'n:' + nm : 'o:' + o.id;
      };
      const PMETH = ['Cash', 'Bank Transfer', 'Easypaisa', 'JazzCash', 'Card'];
      const addPay = (o, amt, method, note) => {
        const a = Math.min(amt, dueOf(o));
        if (a <= 0) return 0;
        o.payments = (o.payments || []).concat([{ id: 'py_' + crypto.randomBytes(4).toString('hex'), at: new Date().toISOString(), amount: a, method, note, by: au.name }]);
        if (dueOf(o) <= 0) o.paid = true;
        return a;
      };

      // quick stock add/remove (with a log of who changed what)
      if (method === 'POST' && b === 'stock') {
        need('prod');
        const body = await readBody(req);
        const products = await getProducts();
        const p = products.find((x) => x.id === str(body.pid, 40));
        if (!p) return send(404, { error: 'Product nahi mila' });
        const ch = (Array.isArray(body.changes) ? body.changes : []).map((c) => ({ size: str(c.size, 20), delta: Math.round(+c.delta) })).filter((c) => c.delta && isFinite(c.delta));
        if (!ch.length) return send(400, { error: 'Koi tabdeeli nahi ki' });
        const reason = str(body.reason, 80), at = new Date().toISOString(), log = (await db.get('stocklog')) || [];
        for (const c of ch) {
          const v = p.variants.find((x) => x.size === c.size);
          if (!v) return send(400, { error: 'Size nahi mila: ' + c.size });
          if (Math.abs(c.delta) > 10000) return send(400, { error: 'Itni bari quantity allowed nahi' });
          if (v.stock + c.delta < 0) return send(400, { error: `${p.name} ${v.size}: stock se zyada remove nahi ho sakta (abhi ${v.stock})` });
        }
        for (const c of ch) {
          const v = p.variants.find((x) => x.size === c.size);
          v.stock += c.delta;
          log.unshift({ at, by: au.name, pid: p.id, pname: p.name, size: v.size, delta: c.delta, after: v.stock, reason });
        }
        await db.set('products', products);
        await db.set('stocklog', log.slice(0, 1000));
        return send(200, { ok: true });
      }

      // ---- Requirement (restock) lists: banao -> maal aaye to receive karo -> stock khud add, baki delete ----
      if (b === 'need' && method === 'POST' && !c) {
        need('prod');
        const body = await readBody(req);
        const products = await getProducts();
        const lines = (Array.isArray(body.lines) ? body.lines : []).slice(0, 200).map((l) => {
          const p = products.find((x) => x.id === str(l.pid, 40));
          const size = NEED_SIZES.find((z) => z === normSize(l.size));
          const qty = Math.round(+l.qty);
          if (!p || !size || !(qty >= 1 && qty <= 10000)) return null;
          return { id: str(l.id, 20) || 'l_' + crypto.randomBytes(4).toString('hex'), pid: p.id, pname: p.name, size, qty, tester: !!l.tester };
        }).filter(Boolean);
        if (!lines.length) return send(400, { error: 'Kam az kam ek perfume, size aur quantity daalein' });
        const list = (await db.get('needs')) || [];
        const i = list.findIndex((x) => x.id === str(body.id, 40));
        if (i >= 0 && list[i].status !== 'open') return send(400, { error: 'Ye list pehle hi done ho chuki hai' });
        const rec = { auto: i >= 0 ? !!list[i].auto : false, id: i >= 0 ? list[i].id : 'n_' + crypto.randomBytes(5).toString('hex'), title: str(body.title, 60) || 'Requirement', status: 'open', createdAt: i >= 0 ? list[i].createdAt : new Date().toISOString(), by: i >= 0 ? list[i].by : au.name, lines };
        if (i >= 0) list[i] = rec; else list.unshift(rec);
        await db.set('needs', list.slice(0, 60));
        return send(200, { ok: true, id: rec.id });
      }
      if (b === 'need' && method === 'DELETE' && c) {
        need('prod');
        const list = (await db.get('needs')) || [];
        await db.set('needs', list.filter((x) => x.id !== c));
        return send(200, { ok: true });
      }
      if (b === 'need' && method === 'POST' && c && parts[3] === 'receive') {
        need('prod');
        const body = await readBody(req);
        const list = (await db.get('needs')) || [];
        const n = list.find((x) => x.id === c);
        if (!n) return send(404, { error: 'List nahi mili' });
        if (n.status !== 'open') return send(400, { error: 'Ye list pehle hi done ho chuki hai' });
        const products = await getProducts();
        const got = body.got || {}, pr = body.prices || {}, costs = au.perms.has('acc') && body.costs && typeof body.costs === 'object' ? body.costs : {};
        const adds = [];
        for (const l of n.lines) {
          const q = Math.max(0, Math.min(10000, Math.round(+got[l.id] || 0)));
          if (!q) continue;
          const p = products.find((x) => x.id === l.pid);
          if (!p) return send(400, { error: l.pname + ' product ab maujood nahi' });
          let v = p.variants.find((x) => normSize(x.size) === l.size), fresh = false;
          if (!v) {
            fresh = true;
            const price = Math.round(+(pr[l.id] && pr[l.id].price));
            if (!(price > 0)) return send(400, { error: `${l.pname} ${l.size}: ye size pehle nahi tha, price daalein` });
            const cost = au.perms.has('acc') ? Math.max(0, Math.round(+(pr[l.id] && pr[l.id].cost) || 0)) : 0;
            v = { size: l.size, price, cost, discount: 0, stock: 0, min: 3 };
            p.variants.push(v);
          }
          const kc = costs[l.id] === '' || costs[l.id] == null ? NaN : Math.round(+costs[l.id]);
          adds.push({ l, p, v, q, fresh, kc: kc >= 0 && kc <= 10000000 ? kc : null });
        }
        if (!adds.length) return send(400, { error: 'Kuch bhi mila nahi likha, pehle quantity daalein (ya list delete kar dein)' });
        const at = new Date().toISOString(), log = (await db.get('stocklog')) || [];
        for (const a of adds) {
          a.v.stock += a.q;
          log.unshift({ at, by: au.name, pid: a.p.id, pname: a.p.name, size: a.v.size, delta: a.q, after: a.v.stock, reason: 'Requirement: ' + n.title + (a.l.tester ? ' (Tester)' : '') });
        }
        let bill = 0;
        for (const a of adds) {
          const unit = a.kc != null ? a.kc : Math.max(0, +a.v.cost || 0);
          if (au.perms.has('acc')) { a.unit = unit; bill += unit * a.q; }
          if (a.kc != null && !a.fresh && body.updateCost === true) a.v.cost = a.kc; // latest purchase cost becomes the product cost
          if (a.fresh && a.kc != null) a.v.cost = a.kc;
        }
        n.lines = adds.map((a) => ({ ...a.l, got: a.q, ...(a.unit != null ? { unitCost: a.unit } : {}) }));
        if (au.perms.has('acc')) n.billTotal = bill;
        n.status = 'done'; n.doneAt = at; n.doneBy = au.name;
        await db.set('products', products);
        await db.set('stocklog', log.slice(0, 1000));
        await db.set('needs', list);
        return send(200, { ok: true, added: adds.length });
      }

      if (method === 'GET' && b === 'data') {
        const [settings, products0, orders0, coupons, expenses0, requests, reviews, staff, deals] = await Promise.all([getSettings(), getProducts(), getOrders(), getCoupons(), getExpenses(), getRequests(), getReviews(), getStaff(), getDeals()]);
        let products = products0, orders = orders0;
        let changed = false;
        for (const o of orders) if (!o.token) { o.token = newToken(); changed = true; }
        if (changed) await db.set('orders', orders);
        const seeCost = au.perms.has('acc');
        if (!seeCost) {
          products = products.map((p) => ({ ...p, variants: p.variants.map(({ cost, ...v }) => v) }));
          orders = orders.map(L.stripCost);
        }
        const stocklog = au.perms.has('prod') ? ((await db.get('stocklog')) || []).slice(0, 600) : [];
        let needs = au.perms.has('prod') ? ((await db.get('needs')) || []) : [];
        if (!au.perms.has('acc')) needs = needs.map(({ billTotal, ...n }) => ({ ...n, lines: n.lines.map(({ unitCost, ...l }) => l) }));
        return send(200, {
          stocklog, needs, settings, products, orders, coupons, deals: au.perms.has('off') ? deals : [], expenses: seeCost ? expenses0 : [], requests, reviews: au.perms.has('rev') ? reviews : [],
          staff: au.owner ? staff.map(({ salt, hash, ...x }) => x) : [],
          me: { owner: au.owner, name: au.name, perms: [...au.perms] },
        });
      }

      // payment screenshot (private: only logged-in admins/staff with order access)
      if (method === 'GET' && b === 'proof' && c) {
        need('ord');
        const d = await db.get('pay:' + c);
        const m = d && /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(d);
        if (!m) { res.statusCode = 404; return res.end('Not found'); }
        res.statusCode = 200;
        res.setHeader('Content-Type', m[1]);
        res.setHeader('Cache-Control', 'private, no-store');
        return res.end(Buffer.from(m[2], 'base64'));
      }

      if (method === 'POST' && b === 'image') {
        if (!au.perms.has('prod') && !au.perms.has('set') && !au.perms.has('off')) need('prod');
        const body = await readBody(req, 1300000);
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
        // record stock changes made through the product form / bulk add
        const ents = [], at = new Date().toISOString();
        if (old) for (const v of np.variants) { const ov = old.variants.find((x) => x.size === v.size); const d = v.stock - (ov ? ov.stock : 0); if (d) ents.push({ at, by: au.name, pid: np.id, pname: np.name, size: v.size, delta: d, after: v.stock, reason: ov ? 'Product edit se badla' : 'Naya size add kiya' }); }
        else for (const v of np.variants) if (v.stock > 0) ents.push({ at, by: au.name, pid: np.id, pname: np.name, size: v.size, delta: v.stock, after: v.stock, reason: 'Naya product (opening stock)' });
        if (ents.length) await db.set('stocklog', ents.reverse().concat((await db.get('stocklog')) || []).slice(0, 1000));
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
        if (o.udhaar) { if (body.paid !== false) addPay(o, dueOf(o), o.payment === 'COD' ? 'Cash' : o.payment, ''); }
        else o.paid = body.paid !== false;
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'order' && c && !parts[3]) {
        need('ord');
        const body = await readBody(req);
        const status = str(body.status, 20);
        if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) return send(400, { error: 'Invalid status' });
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status === 'cancelled') return send(400, { error: 'Cancelled order dobara change nahi ho sakta' });
        if (o.backorder && (status === 'shipped' || status === 'delivered')) return send(400, { error: 'Is order ka kuch maal abhi aaya nahi. Pehle "Maal aa gaya, complete karo" dabayein.' });
        if (status === 'cancelled') {
          const products = await getProducts();
          L.applyStock(products, L.physLines(o.lines), +1);
          await db.set('products', products);
          await backSync(o.lines, -1);
        }
        o.status = status;
        if (status === 'cancelled') { o.cancelReason = str(body.reason, 200); o.cancelledAt = new Date().toISOString(); }
        if (status === 'delivered' && o.payment === 'COD' && !o.udhaar) o.paid = true;
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      // stock has arrived: move waiting (backorder) quantities of this order out of stock, as much as is available
      if (method === 'POST' && b === 'order' && c && parts[3] === 'fulfill') {
        need('ord');
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o || !o.backorder || o.status === 'cancelled') return send(404, { error: 'Is order me koi maal pending nahi' });
        const products = await getProducts();
        let took = 0;
        for (const l of o.lines) {
          if (!(l.back > 0)) continue;
          const p = products.find((x) => x.id === l.pid), v = p && p.variants.find((x) => x.size === l.size);
          const t = v ? Math.min(l.back, Math.max(0, v.stock)) : 0;
          if (t <= 0) continue;
          v.stock -= t; l.back -= t; took += t;
          if (l.back <= 0) delete l.back;
          await needSync(l.pid, l.name, l.size, -t);
        }
        if (!took) return send(400, { error: 'Abhi stock nahi aaya. Pehle Requirement se maal receive karein ya stock add karein.' });
        const left = o.lines.reduce((a, l) => a + (l.back || 0), 0);
        if (!left) o.backorder = false;
        await db.set('products', products);
        await db.set('orders', orders);
        return send(200, { ok: true, took, left });
      }

      // partial return: some items come back, stock goes back, totals are recalculated
      if (method === 'POST' && b === 'order' && c && parts[3] === 'return') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status === 'cancelled') return send(400, { error: 'Order pehle se cancelled hai' });
        const want = (Array.isArray(body.items) ? body.items : []).map((it) => ({ i: Math.round(+it.i), q: Math.round(+it.qty) })).filter((it) => o.lines[it.i] && it.q > 0);
        if (!want.length) return send(400, { error: 'Koi item select nahi kiya' });
        const back = [];
        const newLines = o.lines.map((l, i) => {
          const w = want.find((x) => x.i === i);
          const r = w ? Math.min(w.q, l.qty) : 0;
          const fb = Math.min(l.back || 0, r); // returned qty that was never in stock: just drops off the waiting list
          if (r > 0) back.push({ ...l, qty: r - fb, total: l.unit * r, fromBack: fb });
          if (!(r > 0)) return l;
          const nl = { ...l, qty: l.qty - r, total: l.unit * (l.qty - r) };
          if ((l.back || 0) - fb > 0) nl.back = l.back - fb; else delete nl.back;
          return nl;
        }).filter((l) => l.qty > 0);
        const products = await getProducts();
        L.applyStock(products, back, +1);
        for (const bl of back) if (bl.fromBack) await needSync(bl.pid, bl.name, bl.size, -bl.fromBack);
        if (o.backorder && !newLines.some((l) => l.back > 0)) o.backorder = false;
        await db.set('products', products);
        const reason = str(body.reason, 200);
        if (!newLines.length) {
          o.status = 'cancelled'; o.cancelReason = reason || 'Poora return'; o.cancelledAt = new Date().toISOString();
        } else {
          const oldTotal = o.total, ratio = o.subtotal > 0 ? (o.discount || 0) / o.subtotal : 0;
          const subtotal = newLines.reduce((a, l) => a + l.total, 0);
          const discount = Math.round(subtotal * ratio);
          o.returns = (o.returns || []).concat([{ at: new Date().toISOString(), reason, refund: 0, items: back.map((l) => ({ name: l.name, size: l.size, qty: l.qty, amount: l.total })) }]);
          o.lines = newLines; o.subtotal = subtotal; o.discount = discount;
          o.total = subtotal - discount + (o.delivery || 0);
          o.returns[o.returns.length - 1].refund = oldTotal - o.total;
          if (o.udhaar) o.paid = payRep(o) >= o.total;
        }
        await db.set('orders', orders);
        return send(200, { ok: true, total: o.total, cancelled: o.status === 'cancelled' });
      }

      // permanently delete an order/invoice (owner only); stock goes back if it was not already cancelled
      if (method === 'DELETE' && b === 'order' && c) {
        if (!au.owner) throw L.httpErr(403, 'Sirf owner invoice delete kar sakta hai');
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status !== 'cancelled') {
          const products = await getProducts();
          L.applyStock(products, L.physLines(o.lines), +1);
          await db.set('products', products);
          await backSync(o.lines, -1);
        }
        await db.set('orders', orders.filter((x) => x.id !== c));
        await db.del('pay:' + c);
        return send(200, { ok: true });
      }

      // in-store sale (POS)
      // ---- Udhaar (baad me payment): credit orders, partial payments ----
      if (method === 'POST' && b === 'order' && c && parts[3] === 'credit') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o) return send(404, { error: 'Order nahi mila' });
        if (o.status === 'cancelled') return send(400, { error: 'Cancelled order par udhaar nahi lag sakta' });
        if (body.on === false) {
          if ((o.payments || []).length) return send(400, { error: 'Is order par payment record ho chuki hai, udhaar hata nahi sakte' });
          o.udhaar = false; o.paid = o.source === 'store' || (o.payment === 'COD' && o.status === 'delivered');
        } else if (!o.udhaar) {
          if (o.paid && o.source === 'online' && o.payment !== 'COD') return send(400, { error: 'Is order ki online payment pehle se mil chuki hai' });
          o.udhaar = true; o.paid = false; o.payments = []; o.udhaarAt = new Date().toISOString();
        }
        await db.set('orders', orders);
        return send(200, { ok: true });
      }
      if (method === 'POST' && b === 'order' && c && parts[3] === 'pay') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const o = orders.find((x) => x.id === c);
        if (!o || !o.udhaar) return send(404, { error: 'Udhaar order nahi mila' });
        const amt = Math.round(+body.amount);
        if (!(amt > 0)) return send(400, { error: 'Sahi amount likhein' });
        if (amt > dueOf(o)) return send(400, { error: 'Amount baqaya se zyada hai (baqaya Rs. ' + dueOf(o) + ')' });
        addPay(o, amt, PMETH.includes(body.method) ? body.method : 'Cash', str(body.note, 100));
        await db.set('orders', orders);
        return send(200, { ok: true });
      }
      if (method === 'POST' && b === 'udhaar' && c === 'pay') {
        need('ord');
        const body = await readBody(req);
        const orders = await getOrders();
        const key = str(body.key, 80);
        const list = orders.filter((o) => dueOf(o) > 0 && custKey(o) === key).sort((x, y) => x.createdAt.localeCompare(y.createdAt));
        const total = list.reduce((a, o) => a + dueOf(o), 0);
        let amt = Math.round(+body.amount);
        if (!list.length) return send(404, { error: 'Is customer ka baqaya nahi mila' });
        if (!(amt > 0)) return send(400, { error: 'Sahi amount likhein' });
        if (amt > total) return send(400, { error: 'Amount baqaya se zyada hai (baqaya Rs. ' + total + ')' });
        const m = PMETH.includes(body.method) ? body.method : 'Cash', note = str(body.note, 100);
        for (const o of list) { if (amt <= 0) break; amt -= addPay(o, amt, m, note); }
        await db.set('orders', orders);
        return send(200, { ok: true });
      }

      if (method === 'POST' && b === 'sale') {
        need('sell');
        const body = await readBody(req);
        const [settings, products] = await Promise.all([getSettings(), getProducts()]);
        const lines = L.buildLines(body.items, products, settings, { onlyActive: false, backorder: true });
        const hasBack = lines.some((l) => l.back > 0);
        if (hasBack) {
          const nm0 = str(body.customerName, 80), ph0 = str(body.customerPhone, 20);
          if (!nm0 || nm0.toLowerCase() === 'walk-in' || ph0.replace(/\D/g, '').length < 10) return send(400, { error: 'Jis perfume ka stock nahi, uske order ke liye customer ka naam aur sahi phone number likhein' });
        }
        const t = L.totals(lines, settings, null, body.discount, true);
        const call = body.call === true; // phone / home-delivery order made by staff
        let callInfo = null;
        if (call) {
          const phone = str(body.customerPhone, 20), name = str(body.customerName, 80), address = str(body.address, 200);
          if (!name) return send(400, { error: 'Delivery order ke liye customer ka naam likhein' });
          if (phone.replace(/\D/g, '').length < 10) return send(400, { error: 'Delivery order ke liye sahi phone number likhein' });
          if (!address) return send(400, { error: 'Delivery order ke liye address likhein' });
          const pay = ['COD', 'Bank Transfer', 'Easypaisa', 'JazzCash'].includes(body.payment) ? body.payment : 'COD';
          const dc = Math.max(0, Math.min(5000, Math.round(+body.dc) || 0));
          callInfo = { phone, name, address, city: str(body.city, 60), pay, dc, paid: pay !== 'COD' && body.paid === true };
          t.delivery = dc; t.total = t.total + dc;
        }
        const ud = body.udhaar === true;
        let advance = 0;
        if (ud) {
          const nm = str(body.customerName, 80), ph = str(body.customerPhone, 20);
          if (!nm || nm.toLowerCase() === 'walk-in') return send(400, { error: 'Udhaar ke liye customer ka naam likhein' });
          if (ph.replace(/\D/g, '').length < 10) return send(400, { error: 'Udhaar ke liye customer ka sahi phone number likhein' });
          advance = Math.max(0, Math.round(+body.advance) || 0);
          if (advance >= t.total) return send(400, { error: 'Advance poori payment ke barabar ya zyada hai, to udhaar nahi bante. Udhaar ka tick hata dein' });
        }
        L.applyStock(products, L.physLines(lines), -1);
        const { no, id } = await nextOrderId();
        const order = callInfo ? {
          id, no, token: newToken(), createdAt: new Date().toISOString(), source: 'online', channel: 'call', by: au.name, status: 'pending', dcSet: true,
          payment: callInfo.pay, paymentRef: '', proof: false, paid: callInfo.paid,
          customer: { name: callInfo.name, phone: callInfo.phone, city: callInfo.city, address: callInfo.address, note: str(body.note, 200) },
          lines, ...t, coupon: '',
        } : {
          id, no, token: newToken(), createdAt: new Date().toISOString(), source: 'store', by: au.name, status: 'delivered', dcSet: true,
          payment: ['Cash', 'Card', 'Bank Transfer', 'Easypaisa', 'JazzCash'].includes(body.payment) ? body.payment : 'Cash', paid: true,
          customer: { name: str(body.customerName, 80) || 'Walk-in', phone: str(body.customerPhone, 20), city: '', address: '', note: '' },
          lines, ...t, coupon: '',
        };
        if (hasBack) { order.status = 'pending'; order.backorder = true; }
        if (ud) {
          order.udhaar = true; order.paid = false; order.udhaarAt = order.createdAt; order.payments = [];
          if (advance > 0) order.payments.push({ id: 'py_' + crypto.randomBytes(4).toString('hex'), at: order.createdAt, amount: advance, method: PMETH.includes(body.payment) ? body.payment : 'Cash', note: 'Advance', by: au.name });
        }
        await db.set('products', products);
        if (hasBack) await backSync(lines, +1);
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

      // ----- time-limited deals (bundle of perfumes at one special price) -----
      if (method === 'POST' && b === 'deal' && !c) {
        need('off');
        const body = await readBody(req);
        const products = await getProducts();
        const items = (Array.isArray(body.items) ? body.items : []).slice(0, 6).map((it) => {
          const p = products.find((x) => x.id === str(it.pid, 40)), v = p && p.variants.find((x) => x.size === str(it.size, 20));
          const qty = Math.round(+it.qty);
          return p && v && qty >= 1 && qty <= 5 ? { pid: p.id, size: v.size, qty } : null;
        }).filter(Boolean);
        if (!items.length) return send(400, { error: 'Kam az kam ek perfume (size ke saath) chunein' });
        const price = Math.round(+body.price);
        if (!(price > 0 && price <= 10000000)) return send(400, { error: 'Deal ki price likhein' });
        const st = Date.parse(body.start), en = Date.parse(body.end);
        if (!(st > 0) || !(en > 0)) return send(400, { error: 'Shuru aur khatam hone ka waqt chunein' });
        if (en <= st) return send(400, { error: 'Khatam hone ka waqt shuru se baad ka hona chahiye' });
        const title = str(body.title, 60);
        if (!title) return send(400, { error: 'Deal ka naam likhein' });
        const list = await getDeals();
        const i = list.findIndex((x) => x.id === str(body.id, 40));
        const image = /^[a-f0-9]{16}$/.test(String(body.image || '')) ? String(body.image) : '';
        if (i >= 0 && list[i].image && list[i].image !== image) await db.del('img:' + list[i].image);
        const rec = { image, id: i >= 0 ? list[i].id : 'd_' + crypto.randomBytes(5).toString('hex'), title, subtitle: str(body.subtitle, 100), items, price, start: new Date(st).toISOString(), end: new Date(en).toISOString(), active: body.active !== false, createdAt: i >= 0 ? list[i].createdAt : new Date().toISOString() };
        if (i >= 0) list[i] = rec; else list.unshift(rec);
        await db.set('deals', list.slice(0, 30));
        return send(200, { ok: true, id: rec.id });
      }
      if (method === 'DELETE' && b === 'deal' && c) {
        need('off');
        const all = await getDeals(), gone = all.find((x) => x.id === c);
        if (gone && gone.image) await db.del('img:' + gone.image);
        await db.set('deals', all.filter((x) => x.id !== c));
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

      // ----- change my own password (owner or staff) -----
      if (method === 'POST' && b === 'password') {
        if (await limited(req, 'pwchg', 10, 600)) return send(429, TOO_MANY);
        const body = await readBody(req);
        const cur = String(body.current || ''), next = String(body.next || '');
        if (next.length < (au.owner ? 8 : 6)) return send(400, { error: 'Naya password kam az kam ' + (au.owner ? 8 : 6) + ' huroof ka ho' });
        if (next === cur) return send(400, { error: 'Naya password purane se alag ho' });
        const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
        let ver, uid;
        if (au.owner) {
          if (!(await ownerOk(cur))) { await sleep(800); return send(400, { error: 'Maujooda password galat hai' }); }
          const salt = crypto.randomBytes(12).toString('hex');
          const rec = { salt, hash: hashPw(next, salt), changedAt: new Date().toISOString() };
          await db.set('owner', rec);
          ver = ownerVer(rec); uid = 'owner';
        } else {
          const list = await getStaff();
          const st = list.find((x) => x.id === au.id);
          if (!st || !pwOk(st, cur)) { await sleep(800); return send(400, { error: 'Maujooda password galat hai' }); }
          st.salt = crypto.randomBytes(12).toString('hex'); st.hash = hashPw(next, st.salt);
          await db.set('staff', list);
          ver = verOf(st.hash); uid = st.id;
        }
        const tok = sign({ exp: Date.now() + 7 * 864e5, u: uid, v: ver });
        return send(200, { ok: true }, { 'Set-Cookie': `zt=${tok}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800${secure}` });
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
    return send(e.status || 500, { error: e.status ? e.message : 'Server mein masla aaya, dobara try karein' });
  }
};
