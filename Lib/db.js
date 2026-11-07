// Storage layer: Upstash Redis (Vercel) in production, local JSON file for development.
const fs = require('fs');
const os = require('os');
const path = require('path');

const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const remote = !!(URL_ && TOKEN);

async function cmd(args) {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  const j = await r.json();
  if (j.error) throw new Error('DB: ' + j.error);
  return j.result;
}

// ---- local fallback (dev only) ----
const FILE = path.join(process.env.ZEEN_DATA_DIR || os.tmpdir(), 'zeen-data.json');
let mem = null;
function load() {
  if (mem) return mem;
  try { mem = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { mem = {}; }
  return mem;
}
function save() { try { fs.writeFileSync(FILE, JSON.stringify(mem)); } catch {} }

function assertReady() {
  if (!remote && process.env.VERCEL) {
    const e = new Error('Database connect nahi hai. Vercel > Storage mein Upstash Redis connect karein.');
    e.status = 500;
    throw e;
  }
}

module.exports = {
  remote,
  async get(key) {
    assertReady();
    if (remote) {
      const v = await cmd(['GET', key]);
      return v == null ? null : JSON.parse(v);
    }
    const v = load()[key];
    return v === undefined ? null : JSON.parse(JSON.stringify(v));
  },
  async set(key, val) {
    assertReady();
    if (remote) return cmd(['SET', key, JSON.stringify(val)]);
    load()[key] = JSON.parse(JSON.stringify(val));
    save();
  },
  async del(key) {
    assertReady();
    if (remote) return cmd(['DEL', key]);
    delete load()[key];
    save();
  },
  async incr(key) {
    assertReady();
    if (remote) return cmd(['INCR', key]);
    const m = load();
    m[key] = (Number(m[key]) || 0) + 1;
    save();
    return m[key];
  },
};
