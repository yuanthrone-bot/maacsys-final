import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

let useMemoryStore = false;
const memoryTeachers = [];

function isStrongPassword(value) {
  return value.length >= 8 && /[A-Z]/.test(value) && /\d/.test(value);
}

function normalizeCell(countryCode, cell) {
  return `${countryCode}${cell}`.replace(/\s+/g, '');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, hash] = storedHash.split(':');
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return derived === hash;
}

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function normalizeUsername(value) {
  return value.trim().toLowerCase();
}

async function sendSms(to, message) {
  const endpoint = process.env.PHILSMS_ENDPOINT || process.env.PHILSMS_API_URL;
  if (!endpoint) {
    return { ok: true, note: 'SMS skipped because no endpoint is configured.' };
  }

  const payload = {
    to,
    message,
    senderId: process.env.PHILSMS_SENDER_ID || 'MAACSYS',
  };

  const headers = { 'Content-Type': 'application/json' };
  if (process.env.PHILSMS_API_KEY) {
    headers.Authorization = `Bearer ${process.env.PHILSMS_API_KEY}`;
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });

  const text = await response.text();
  return { ok: response.ok, status: response.status, body: text };
}

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS teachers (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        cell TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        verification_code TEXT,
        verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    return true;
  } catch (error) {
    console.warn('PostgreSQL unavailable, using in-memory teacher store:', error.message);
    useMemoryStore = true;
    return false;
  }
}

await initDb();

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'MAACSYS API' });
});

app.get('/', (_req, res) => {
  const candidates = ['MAACSYS MAIN.html', 'MAACSYS MAIN', 'index.html'];
  const fileName = candidates.find((name) => fs.existsSync(path.join(__dirname, name)));
  if (!fileName) {
    return res.status(404).send('MAACSYS entry page not found.');
  }

  res.sendFile(path.join(__dirname, fileName));
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, cell, password, countryCode } = req.body || {};

    if (!username || !cell || !password || !countryCode) {
      return res.status(400).json({ error: 'Please complete all registration fields.' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({ error: 'Password is too weak. Use 8+ characters, uppercase and a number.' });
    }

    const normalizedCell = normalizeCell(countryCode, cell);

    if (useMemoryStore) {
      const duplicate = memoryTeachers.find((teacher) => normalizeUsername(teacher.username) === normalizeUsername(username) || teacher.cell === normalizedCell);
      if (duplicate) {
        return res.status(409).json({ error: 'Username or cell number already exists.' });
      }

      const code = generateCode();
      const passwordHash = hashPassword(password);
      memoryTeachers.push({
        id: memoryTeachers.length + 1,
        username,
        cell: normalizedCell,
        password_hash: passwordHash,
        verification_code: code,
        verified: false,
      });

      await sendSms(normalizedCell, `MAACSYS verification code: ${code}`);
      return res.json({
        success: true,
        message: 'Registration accepted. Enter the verification code.',
        verificationCode: process.env.NODE_ENV !== 'production' ? code : undefined,
      });
    }

    const existing = await pool.query(
      'SELECT id FROM teachers WHERE LOWER(username) = LOWER($1) OR cell = $2',
      [username, normalizedCell]
    );

    if (existing.rows.length) {
      return res.status(409).json({ error: 'Username or cell number already exists.' });
    }

    const code = generateCode();
    const passwordHash = hashPassword(password);
    await pool.query(
      'INSERT INTO teachers (username, cell, password_hash, verification_code, verified) VALUES ($1, $2, $3, $4, FALSE)',
      [username, normalizedCell, passwordHash, code]
    );

    await sendSms(normalizedCell, `MAACSYS verification code: ${code}`);

    return res.json({
      success: true,
      message: 'Registration accepted. Enter the verification code.',
      verificationCode: process.env.NODE_ENV !== 'production' ? code : undefined,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { username, code } = req.body || {};
    if (!username || !code) {
      return res.status(400).json({ error: 'Please provide the username and verification code.' });
    }

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username));
      if (!teacher || teacher.verification_code !== code) {
        return res.status(400).json({ error: 'The verification code is incorrect.' });
      }

      teacher.verified = true;
      teacher.verification_code = null;
      return res.json({ success: true, message: 'Successful registration. You may now log in.' });
    }

    const result = await pool.query(
      'SELECT id, verification_code FROM teachers WHERE LOWER(username) = LOWER($1)',
      [username]
    );

    const teacher = result.rows[0];
    if (!teacher || teacher.verification_code !== code) {
      return res.status(400).json({ error: 'The verification code is incorrect.' });
    }

    await pool.query(
      'UPDATE teachers SET verified = TRUE, verification_code = NULL WHERE id = $1',
      [teacher.id]
    );

    return res.json({ success: true, message: 'Successful registration. You may now log in.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Verification failed.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Please enter your username and password.' });
    }

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username));
      if (!teacher || !verifyPassword(password, teacher.password_hash) || !teacher.verified) {
        return res.status(401).json({ error: 'Login details are incorrect or the account is not verified.' });
      }

      return res.json({ success: true, message: 'Login successful.', user: { username: teacher.username, cell: teacher.cell } });
    }

    const result = await pool.query('SELECT id, username, cell, password_hash, verified FROM teachers WHERE LOWER(username) = LOWER($1)', [username]);
    const teacher = result.rows[0];

    if (!teacher || !verifyPassword(password, teacher.password_hash) || !teacher.verified) {
      return res.status(401).json({ error: 'Login details are incorrect or the account is not verified.' });
    }

    return res.json({ success: true, message: 'Login successful.', user: { username: teacher.username, cell: teacher.cell } });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { username, cell } = req.body || {};
    if (!username || !cell) {
      return res.status(400).json({ error: 'Please enter your registered username and cell number.' });
    }

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username) && entry.cell === cell);
      if (!teacher) {
        return res.status(404).json({ error: 'No matching account was found.' });
      }

      const code = generateCode();
      teacher.verification_code = code;
      await sendSms(cell, `MAACSYS password reset code: ${code}`);
      return res.json({ success: true, message: 'A code has been sent to your number.' });
    }

    const result = await pool.query(
      'SELECT id, cell FROM teachers WHERE LOWER(username) = LOWER($1) AND cell = $2',
      [username, cell]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: 'No matching account was found.' });
    }

    const code = generateCode();
    await pool.query('UPDATE teachers SET verification_code = $1 WHERE id = $2', [code, result.rows[0].id]);
    await sendSms(cell, `MAACSYS password reset code: ${code}`);

    return res.json({ success: true, message: 'A code has been sent to your number.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Password reset request failed.' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { username, cell, code, newPassword } = req.body || {};
    if (!username || !cell || !code || !newPassword) {
      return res.status(400).json({ error: 'Please complete the password reset form.' });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({ error: 'Password is too weak. Use 8+ characters, uppercase and a number.' });
    }

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username) && entry.cell === cell);
      if (!teacher || teacher.verification_code !== code) {
        return res.status(400).json({ error: 'The verification code is incorrect.' });
      }

      teacher.password_hash = hashPassword(newPassword);
      teacher.verification_code = null;
      return res.json({ success: true, message: 'Password updated successfully.' });
    }

    const result = await pool.query(
      'SELECT id, verification_code FROM teachers WHERE LOWER(username) = LOWER($1) AND cell = $2',
      [username, cell]
    );

    const teacher = result.rows[0];
    if (!teacher || teacher.verification_code !== code) {
      return res.status(400).json({ error: 'The verification code is incorrect.' });
    }

    const passwordHash = hashPassword(newPassword);
    await pool.query(
      'UPDATE teachers SET password_hash = $1, verification_code = NULL WHERE id = $2',
      [passwordHash, teacher.id]
    );

    return res.json({ success: true, message: 'Password updated successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Password reset failed.' });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`MAACSYS API listening on port ${port}`);
});
