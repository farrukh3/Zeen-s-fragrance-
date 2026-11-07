// Pricing, stock and order logic (all money is calculated on the server).

const DEFAULT_SETTINGS = {
  shopName: "Zeen's Fragrance",
  tagline: 'Luxury Perfumes, Delivered To Your Door',
  heroTitle: 'Find Your Signature Scent',
  heroSub: 'Long-lasting perfumes in 50ml & 30ml. Cash on delivery all over Pakistan.',
  announcement: 'Free delivery on orders above Rs. 3000',
  whatsapp: '', // e.g. 923001234567
  phone: '',
  address: '',
  instagram: '',
  deliveryCharge: 250,
  freeDeliveryAbove: 3000,
  globalDiscount: { pct: 0, label: '' },
  logo: '',
  heroImage: '',
  facebook: '',
  deliveryMode: 'note', // 'note' = only show a message, 'fixed' = add deliveryCharge to the total
  deliveryNote: 'Delivery charges: up to Rs. 400 depending on your area. Courier charges are paid separately and are not included in the total.',
  payments: {
    cod: { enabled: true },
    bank: { enabled: false, bankName: '', title: '', number: '' },
    easypaisa: { enabled: false, title: '', number: '' },
    jazzcash: { enabled: false, title: '', number: '' },
  },
  invoiceNote: "Thank you for shopping with us! We hope you love your perfume. Please order again and share your feedback with us.",
  invoiceTerms: '',
  theme: { bg: '#0d2019', card: '#163226', accent: '#c9a24b', ink: '#f4efe3' },
};

const SAMPLE_PRODUCTS = () => [
  mk('Royal Oud', 'men', 'A deep, warm and woody perfume for evenings and special occasions.',
    ['Bergamot', 'Saffron'], ['Oud', 'Rose'], ['Amber', 'Musk'], 'Best Seller', true),
  mk('Velvet Rose', 'women', 'A soft floral fragrance with a creamy, romantic finish.',
    ['Pink Pepper', 'Peach'], ['Rose', 'Jasmine'], ['Vanilla', 'Sandalwood'], 'New', true),
  mk('Aqua Breeze', 'unisex', 'Fresh and clean, made for daily wear in hot weather.',
    ['Lemon', 'Mint'], ['Sea Notes', 'Lavender'], ['Cedar', 'White Musk'], '', false),
];
function mk(name, category, description, top, heart, base, badge, featured) {
  return {
    id: 'p_' + Math.random().toString(36).slice(2, 10),
    name, brand: "Zeen's Fragrance", category, description,
    notes: { top, heart, base }, images: [], badge, featured, active: true,
    variants: [
      { size: '50ml', price: 1500, cost: 900, discount: 10, stock: 10 },
      { size: '30ml', price: 1000, cost: 600, discount: 15, stock: 10 },
    ],
    createdAt: new Date().toISOString(),
  };
}

const clamp = (n, a, b) => Math.min(b, Math.max(a, n));
const num = (v, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d);

function variantPrice(v, settings) {
  const g = num(settings.globalDiscount && settings.globalDiscount.pct);
  const pct = clamp(Math.max(num(v.discount), g), 0, 95);
  const price = Math.max(0, Math.round(num(v.price)));
  return { pct, final: Math.round(price * (1 - pct / 100)) };
}

function publicProduct(p, settings) {
  return {
    id: p.id, name: p.name, brand: p.brand, category: p.category, description: p.description,
    notes: p.notes, images: p.images, badge: p.badge, featured: !!p.featured,
    variants: p.variants.map((v) => {
      const { pct, final } = variantPrice(v, settings);
      return { size: v.size, price: v.price, pct, final, stock: Math.max(0, num(v.stock)) };
    }),
  };
}

function cleanList(x) {
  if (Array.isArray(x)) return x.map((s) => String(s).trim()).filter(Boolean).slice(0, 12);
  return String(x || '').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 12);
}

function cleanProduct(b, old) {
  const name = String(b.name || '').trim().slice(0, 80);
  if (!name) throw httpErr(400, 'Product ka naam zaroori hai');
  const variants = (Array.isArray(b.variants) ? b.variants : [])
    .map((v) => ({
      size: String(v.size || '').trim().slice(0, 20),
      price: Math.max(0, Math.round(num(v.price))),
      cost: Math.max(0, Math.round(num(v.cost))),
      discount: clamp(Math.round(num(v.discount)), 0, 95),
      stock: Math.max(0, Math.round(num(v.stock))),
    }))
    .filter((v) => v.size);
  if (!variants.length) throw httpErr(400, 'Kam az kam ek size (e.g. 50ml) add karein');
  return {
    id: old ? old.id : 'p_' + Math.random().toString(36).slice(2, 10),
    name,
    brand: String(b.brand || "Zeen's Fragrance").trim().slice(0, 60),
    category: ['men', 'women', 'unisex'].includes(b.category) ? b.category : 'unisex',
    description: String(b.description || '').slice(0, 1500),
    notes: { top: cleanList(b.notes && b.notes.top), heart: cleanList(b.notes && b.notes.heart), base: cleanList(b.notes && b.notes.base) },
    images: (Array.isArray(b.images) ? b.images : []).filter((s) => /^[\w-]{4,40}$/.test(s)).slice(0, 4),
    badge: String(b.badge || '').trim().slice(0, 20),
    featured: !!b.featured,
    active: b.active !== false,
    variants,
    createdAt: old ? old.createdAt : new Date().toISOString(),
  };
}

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// Build order lines from {pid,size,qty}. Throws if stock is not enough.
function buildLines(items, products, settings, { onlyActive }) {
  if (!Array.isArray(items) || !items.length) throw httpErr(400, 'Cart khaali hai');
  const need = {};
  const lines = items.slice(0, 40).map((it) => {
    const p = products.find((x) => x.id === it.pid && (!onlyActive || x.active));
    const v = p && p.variants.find((x) => x.size === it.size);
    if (!p || !v) throw httpErr(400, 'Ek product ab available nahi hai');
    const qty = clamp(Math.round(num(it.qty, 1)), 1, 50);
    const k = p.id + '|' + v.size;
    need[k] = (need[k] || 0) + qty;
    if (need[k] > num(v.stock)) {
      throw httpErr(400, `${p.name} (${v.size}): sirf ${Math.max(0, num(v.stock))} bacha hai`);
    }
    const { final } = variantPrice(v, settings);
    return { pid: p.id, name: p.name, size: v.size, qty, orig: v.price, unit: final, total: final * qty, cost: Math.max(0, num(v.cost)) };
  });
  return lines;
}

function couponDiscount(c, subtotal) {
  if (!c || !c.active) return 0;
  if (c.expires && new Date(c.expires + 'T23:59:59') < new Date()) return 0;
  if (subtotal < num(c.minOrder)) return 0;
  const d = c.type === 'fixed' ? num(c.value) : Math.round((subtotal * num(c.value)) / 100);
  return clamp(Math.round(d), 0, subtotal);
}

function totals(lines, settings, coupon, extraDiscount = 0, forceNoDelivery = false) {
  const subtotal = lines.reduce((s, l) => s + l.total, 0);
  const cd = couponDiscount(coupon, subtotal);
  const after = subtotal - cd - clamp(Math.round(num(extraDiscount)), 0, subtotal - cd);
  const free = forceNoDelivery || (num(settings.freeDeliveryAbove) > 0 && after >= num(settings.freeDeliveryAbove));
  const delivery = free || settings.deliveryMode !== 'fixed' ? 0 : Math.max(0, num(settings.deliveryCharge));
  return { subtotal, discount: subtotal - after, delivery, total: after + delivery };
}

function applyStock(products, lines, sign) {
  for (const l of lines) {
    const p = products.find((x) => x.id === l.pid);
    const v = p && p.variants.find((x) => x.size === l.size);
    if (v) v.stock = Math.max(0, num(v.stock) + sign * l.qty);
  }
}

const stripCost = (o) => ({ ...o, lines: o.lines.map(({ cost, ...l }) => l) });

module.exports = {
  stripCost,
  DEFAULT_SETTINGS, SAMPLE_PRODUCTS, variantPrice, publicProduct, cleanProduct, cleanList,
  buildLines, couponDiscount, totals, applyStock, httpErr, num, clamp,
};
