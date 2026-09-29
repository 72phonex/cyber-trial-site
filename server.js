const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const REQUIRED_ENV = ['DATABASE_URL', 'FLAG_CRYPTO', 'FLAG_STEGO', 'FLAG_PWN', 'ADMIN_KEY'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error('Missing required environment variables:', missing.join(', '));
  console.error('Set these in the Render dashboard under your service > Environment.');
  process.exit(1);
}

const FLAGS = [process.env.FLAG_CRYPTO, process.env.FLAG_STEGO, process.env.FLAG_PWN];
const ADMIN_KEY = process.env.ADMIN_KEY;

const HINTS = [
  [
    "The message passes through more than one layer — peel the outer one first.",
    "Once you strip that layer, the flag's own format can help you recover the key hiding underneath."
  ],
  [
    "Not everything in a file is meant to be seen with your eyes.",
    "Colour values carry more than colour — the smallest bit of each channel can hide a message."
  ],
  [
    "Try giving the program more input than it expects, and see what it does with the extra.",
    "Every function in this binary is a potential destination — even ones nothing ever calls directly."
  ]
];

const CRYPTO_CIPHERTEXT = 'RlY4Q0VnbERGa0VRSEFGSEZsMEFFQzFERWtvUUtoMVZGVTQ9';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS candidates (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      deadline TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS progress (
      candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
      task_index INTEGER NOT NULL,
      solved BOOLEAN NOT NULL DEFAULT false,
      solved_at TIMESTAMPTZ,
      hint_level INTEGER NOT NULL DEFAULT 0,
      attempts INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (candidate_id, task_index)
    );
    CREATE TABLE IF NOT EXISTS submissions (
      id SERIAL PRIMARY KEY,
      candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
      task_index INTEGER NOT NULL,
      correct BOOLEAN NOT NULL,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

function genCode() {
  return 'CS-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

async function createCandidate() {
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = genCode();
    try {
      const deadline = new Date(Date.now() + 45 * 60 * 1000);
      const { rows } = await pool.query(
        'INSERT INTO candidates (code, deadline) VALUES ($1, $2) RETURNING id, code, deadline',
        [code, deadline]
      );
      const candidate = rows[0];
      const values = [0, 1, 2].map((i) => `(${candidate.id}, ${i})`).join(',');
      await pool.query(`INSERT INTO progress (candidate_id, task_index) VALUES ${values}`);
      return candidate;
    } catch (err) {
      if (err.code === '23505') continue; // code collision, retry
      throw err;
    }
  }
  throw new Error('Could not allocate a unique candidate code');
}

async function getCandidateByCode(code) {
  const { rows } = await pool.query('SELECT id, code, deadline FROM candidates WHERE code = $1', [code]);
  return rows[0] || null;
}

async function getProgress(candidateId) {
  const { rows } = await pool.query(
    'SELECT task_index, solved, solved_at, hint_level FROM progress WHERE candidate_id = $1 ORDER BY task_index',
    [candidateId]
  );
  return rows;
}

// ---- genuine crypto analysis (no flag/plaintext ever leaves this) ----
function shannonEntropy(buf) {
  if (!buf.length) return 0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let e = 0;
  for (const c of counts) { if (c) { const p = c / buf.length; e -= p * Math.log2(p); } }
  return e;
}
function printableRatio(buf) {
  if (!buf.length) return 0;
  let c = 0;
  for (const b of buf) if (b >= 32 && b <= 126) c++;
  return c / buf.length;
}
function tryB64(buf) {
  const s = buf.toString('latin1').trim();
  if (s.length < 8 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try { return Buffer.from(s, 'base64'); } catch (e) { return null; }
}
function peelLayers(buf) {
  let cur = buf, layers = [];
  for (let i = 0; i < 6; i++) {
    const b64 = tryB64(cur);
    if (b64 && (printableRatio(b64) > 0.85 || b64.length !== cur.length)) { layers.push('base64'); cur = b64; continue; }
    break;
  }
  return { layers, core: cur };
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/challenges', express.static(path.join(__dirname, 'challenges')));

app.get('/healthz', (req, res) => res.send('ok'));

app.post('/api/session', async (req, res) => {
  try {
    const code = (req.body && req.body.code || '').trim();
    let candidate = code ? await getCandidateByCode(code) : null;
    if (!candidate) candidate = await createCandidate();
    const progress = await getProgress(candidate.id);
    const enriched = progress.map(p => ({
      ...p,
      hint_text: p.hint_level > 0 ? HINTS[p.task_index][p.hint_level - 1] : null
    }));
    res.json({ code: candidate.code, deadline: candidate.deadline, progress: enriched });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'session_failed' });
  }
});

app.post('/api/submit', async (req, res) => {
  try {
    const { code, taskIndex, value } = req.body || {};
    if (![0, 1, 2].includes(taskIndex) || typeof value !== 'string') {
      return res.status(400).json({ error: 'bad_request' });
    }
    const candidate = await getCandidateByCode((code || '').trim());
    if (!candidate) return res.status(404).json({ error: 'unknown_candidate' });

    const correct = value.trim() === FLAGS[taskIndex];
    await pool.query(
      'INSERT INTO submissions (candidate_id, task_index, correct) VALUES ($1,$2,$3)',
      [candidate.id, taskIndex, correct]
    );
    await pool.query(
      'UPDATE progress SET attempts = attempts + 1 WHERE candidate_id=$1 AND task_index=$2',
      [candidate.id, taskIndex]
    );
    if (correct) {
      await pool.query(
        'UPDATE progress SET solved=true, solved_at=now() WHERE candidate_id=$1 AND task_index=$2 AND solved=false',
        [candidate.id, taskIndex]
      );
    }
    const progress = await getProgress(candidate.id);
    res.json({ correct, progress });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'submit_failed' });
  }
});

app.post('/api/hint', async (req, res) => {
  try {
    const { code, taskIndex } = req.body || {};
    if (![0, 1, 2].includes(taskIndex)) return res.status(400).json({ error: 'bad_request' });
    const candidate = await getCandidateByCode((code || '').trim());
    if (!candidate) return res.status(404).json({ error: 'unknown_candidate' });

    const { rows } = await pool.query(
      'UPDATE progress SET hint_level = LEAST(hint_level+1,2) WHERE candidate_id=$1 AND task_index=$2 RETURNING hint_level',
      [candidate.id, taskIndex]
    );
    const level = rows[0].hint_level;
    res.json({ level, text: HINTS[taskIndex][level - 1] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'hint_failed' });
  }
});

app.post('/api/analyze/crypto', (req, res) => {
  const ciphertext = Buffer.from(CRYPTO_CIPHERTEXT, 'latin1');
  const { layers, core } = peelLayers(ciphertext);
  const ent = shannonEntropy(core);
  const pr = printableRatio(core);
  const suspicious = pr < 0.5 && ent < 7.5;
  res.json({
    length: ciphertext.length,
    layersDetected: layers.length,
    layerChain: layers.join(' -> ') || 'none',
    coreEntropyBitsPerByte: Number(ent.toFixed(3)),
    corePrintableRatio: Number(pr.toFixed(3)),
    suspicious,
    note: suspicious
      ? 'Core payload has low entropy and a low printable ratio after removing the outer encoding — consistent with a repeating-key XOR cipher, not real encryption.'
      : 'No further encoding layers detected.'
  });
});

app.get('/api/leaderboard', async (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  const { rows } = await pool.query(`
    SELECT c.code, c.created_at,
      COALESCE(bool_or(p.task_index=0 AND p.solved), false) AS crypto_solved,
      COALESCE(bool_or(p.task_index=1 AND p.solved), false) AS stego_solved,
      COALESCE(bool_or(p.task_index=2 AND p.solved), false) AS pwn_solved,
      MAX(p.solved_at) AS last_solved_at,
      SUM(p.attempts) AS total_attempts
    FROM candidates c
    LEFT JOIN progress p ON p.candidate_id = c.id
    GROUP BY c.id, c.code, c.created_at
    ORDER BY last_solved_at DESC NULLS LAST, c.created_at ASC
  `);
  res.json(rows);
});

const PORT = process.env.PORT || 3000;
migrate()
  .then(() => app.listen(PORT, () => console.log('CYBER//TRIAL listening on', PORT)))
  .catch((err) => { console.error('Migration failed:', err); process.exit(1); });
