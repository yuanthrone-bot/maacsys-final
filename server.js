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

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS teachers (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        cell TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        prs_number TEXT,
        verified BOOLEAN DEFAULT TRUE,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Patch any pre-existing teachers table that predates these columns.
    await pool.query(`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS prs_number TEXT`);
    await pool.query(`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT TRUE`);
    await pool.query(`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS verification_code TEXT`);
    await pool.query(`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_change_requests (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        new_password_hash TEXT NOT NULL,
        requested_at TIMESTAMP DEFAULT NOW(),
        status TEXT DEFAULT 'pending',
        approved_by TEXT,
        approved_at TIMESTAMP,
        FOREIGN KEY (username) REFERENCES teachers(username)
      )
    `);

    return true;
  } catch (error) {
    console.warn('PostgreSQL unavailable, using in-memory store:', error.message);
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
  if (!fileName) return res.status(404).send('MAACSYS entry page not found.');
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
      if (duplicate) return res.status(409).json({ error: 'Username or cell number already exists.' });

      const passwordHash = hashPassword(password);
      memoryTeachers.push({ id: memoryTeachers.length + 1, username, cell: normalizedCell, password_hash: passwordHash, verified: true, is_admin: false });

      return res.json({ success: true, message: 'Registration successful. You can now log in.', user: { username, is_admin: false } });
    }

    const existing = await pool.query('SELECT id FROM teachers WHERE LOWER(username) = LOWER($1) OR cell = $2', [username, normalizedCell]);
    if (existing.rows.length) return res.status(409).json({ error: 'Username or cell number already exists.' });

    const passwordHash = hashPassword(password);
    await pool.query('INSERT INTO teachers (username, cell, password_hash, verified, is_admin) VALUES ($1, $2, $3, TRUE, FALSE)', [username, normalizedCell, passwordHash]);

    return res.json({ success: true, message: 'Registration successful. You can now log in.', user: { username, is_admin: false } });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Please enter your username and password.' });

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username));
      if (!teacher || !verifyPassword(password, teacher.password_hash) || !teacher.verified) return res.status(401).json({ error: 'Login details are incorrect or the account is not verified.' });
      return res.json({ success: true, message: 'Login successful.', user: { username: teacher.username, cell: teacher.cell, is_admin: teacher.is_admin || false } });
    }

    const result = await pool.query('SELECT id, username, cell, password_hash, verified, is_admin FROM teachers WHERE LOWER(username) = LOWER($1)', [username]);
    const teacher = result.rows[0];
    if (!teacher || !verifyPassword(password, teacher.password_hash) || !teacher.verified) return res.status(401).json({ error: 'Login details are incorrect or the account is not verified.' });
    return res.json({ success: true, message: 'Login successful.', user: { username: teacher.username, cell: teacher.cell, is_admin: teacher.is_admin || false } });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { username, cell } = req.body || {};
    if (!username || !cell) return res.status(400).json({ error: 'Please enter your registered username and cell number.' });

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username) && entry.cell === cell);
      if (!teacher) return res.status(404).json({ error: 'No matching account was found.' });
      const code = generateCode();
      teacher.verification_code = code;
      await sendSms(cell, `MAACSYS password reset code: ${code}`);
      return res.json({ success: true, message: 'A code has been sent to your number.' });
    }

    const result = await pool.query('SELECT id, cell FROM teachers WHERE LOWER(username) = LOWER($1) AND cell = $2', [username, cell]);
    if (!result.rows[0]) return res.status(404).json({ error: 'No matching account was found.' });

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
    if (!username || !cell || !code || !newPassword) return res.status(400).json({ error: 'Please complete the password reset form.' });
    if (!isStrongPassword(newPassword)) return res.status(400).json({ error: 'Password is too weak. Use 8+ characters, uppercase and a number.' });

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username) && entry.cell === cell);
      if (!teacher || teacher.verification_code !== code) return res.status(400).json({ error: 'The verification code is incorrect.' });
      teacher.password_hash = hashPassword(newPassword);
      teacher.verification_code = null;
      return res.json({ success: true, message: 'Password updated successfully.' });
    }

    const result = await pool.query('SELECT id, verification_code FROM teachers WHERE LOWER(username) = LOWER($1) AND cell = $2', [username, cell]);
    const teacher = result.rows[0];
    if (!teacher || teacher.verification_code !== code) return res.status(400).json({ error: 'The verification code is incorrect.' });

    const passwordHash = hashPassword(newPassword);
    await pool.query('UPDATE teachers SET password_hash = $1, verification_code = NULL WHERE id = $2', [passwordHash, teacher.id]);
    return res.json({ success: true, message: 'Password updated successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Password reset failed.' });
  }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const { username, currentPassword, newPassword } = req.body || {};
    if (!username || !currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Please provide all required fields.' });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({ error: 'New password is too weak. Use 8+ characters, uppercase and a number.' });
    }

    if (useMemoryStore) {
      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(username));
      if (!teacher) return res.status(404).json({ error: 'User not found.' });

      if (!verifyPassword(currentPassword, teacher.password_hash)) {
        return res.status(401).json({ error: 'Current password is incorrect.' });
      }

      const newPasswordHash = hashPassword(newPassword);
      const request = {
        username,
        new_password_hash: newPasswordHash,
        requested_at: new Date(),
        status: 'pending'
      };
      
      if (!global.passwordRequests) global.passwordRequests = [];
      global.passwordRequests.push(request);

      return res.json({ success: true, message: 'Password change request submitted. Awaiting admin approval.' });
    }

    const teacher = await pool.query('SELECT password_hash FROM teachers WHERE LOWER(username) = LOWER($1)', [username]);
    if (!teacher.rows[0]) return res.status(404).json({ error: 'User not found.' });

    if (!verifyPassword(currentPassword, teacher.rows[0].password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const newPasswordHash = hashPassword(newPassword);
    await pool.query('INSERT INTO password_change_requests (username, new_password_hash, status) VALUES ($1, $2, $3)', 
      [username, newPasswordHash, 'pending']);

    return res.json({ success: true, message: 'Password change request submitted. Awaiting admin approval.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Password change request failed.' });
  }
});

app.post('/api/admin/pending-requests', async (req, res) => {
  try {
    const { adminUsername } = req.body || {};
    
    if (useMemoryStore) {
      const admin = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(adminUsername));
      if (!admin || !admin.is_admin) {
        return res.status(403).json({ error: 'Admin access required.' });
      }
      
      if (!global.passwordRequests) global.passwordRequests = [];
      const pending = global.passwordRequests.filter(r => r.status === 'pending');
      return res.json({ success: true, requests: pending });
    }

    const admin = await pool.query('SELECT is_admin FROM teachers WHERE LOWER(username) = LOWER($1)', [adminUsername]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    const requests = await pool.query('SELECT id, username, requested_at, status FROM password_change_requests WHERE status = $1 ORDER BY requested_at DESC', 
      ['pending']);
    
    return res.json({ success: true, requests: requests.rows });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Failed to fetch requests.' });
  }
});

app.post('/api/admin/approve-request', async (req, res) => {
  try {
    const { requestId, adminUsername } = req.body || {};
    
    if (useMemoryStore) {
      const admin = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(adminUsername));
      if (!admin || !admin.is_admin) {
        return res.status(403).json({ error: 'Admin access required.' });
      }

      if (!global.passwordRequests) global.passwordRequests = [];
      const request = global.passwordRequests.find(r => r.id === requestId);
      if (!request) return res.status(404).json({ error: 'Request not found.' });

      const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(request.username));
      if (teacher) {
        teacher.password_hash = request.new_password_hash;
      }

      request.status = 'approved';
      request.approved_by = adminUsername;
      request.approved_at = new Date();

      return res.json({ success: true, message: 'Password change approved.' });
    }

    const admin = await pool.query('SELECT is_admin FROM teachers WHERE LOWER(username) = LOWER($1)', [adminUsername]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    const request = await pool.query('SELECT username, new_password_hash FROM password_change_requests WHERE id = $1 AND status = $2', 
      [requestId, 'pending']);
    if (!request.rows[0]) return res.status(404).json({ error: 'Request not found.' });

    await pool.query('UPDATE teachers SET password_hash = $1 WHERE LOWER(username) = LOWER($2)', 
      [request.rows[0].new_password_hash, request.rows[0].username]);

    await pool.query('UPDATE password_change_requests SET status = $1, approved_by = $2, approved_at = NOW() WHERE id = $3', 
      ['approved', adminUsername, requestId]);

    return res.json({ success: true, message: 'Password change approved.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Failed to approve request.' });
  }
});

app.post('/api/admin/reject-request', async (req, res) => {
  try {
    const { requestId, adminUsername } = req.body || {};
    
    if (useMemoryStore) {
      const admin = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(adminUsername));
      if (!admin || !admin.is_admin) {
        return res.status(403).json({ error: 'Admin access required.' });
      }

      if (!global.passwordRequests) global.passwordRequests = [];
      const request = global.passwordRequests.find(r => r.id === requestId);
      if (!request) return res.status(404).json({ error: 'Request not found.' });

      request.status = 'rejected';
      request.approved_by = adminUsername;
      request.approved_at = new Date();

      return res.json({ success: true, message: 'Password change rejected.' });
    }

    const admin = await pool.query('SELECT is_admin FROM teachers WHERE LOWER(username) = LOWER($1)', [adminUsername]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    await pool.query('UPDATE password_change_requests SET status = $1, approved_by = $2, approved_at = NOW() WHERE id = $3', 
      ['rejected', adminUsername, requestId]);

    return res.json({ success: true, message: 'Password change rejected.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Failed to reject request.' });
  }
});

async function ensureAdmin() {
  const adminUsername = process.env.ADMIN_USERNAME;
  if (!adminUsername) {
    console.log('ADMIN_USERNAME not set - skipping admin bootstrap.');
    return;
  }

  if (useMemoryStore) {
    const teacher = memoryTeachers.find((entry) => normalizeUsername(entry.username) === normalizeUsername(adminUsername));
    if (!teacher) {
      console.warn(`ADMIN_USERNAME "${adminUsername}" not found (in-memory store). Register that account first, then restart the server.`);
      return;
    }
    if (!teacher.is_admin) {
      teacher.is_admin = true;
      console.log(`Granted admin to "${adminUsername}" (in-memory store).`);
    }
    return;
  }

  try {
    const result = await pool.query('SELECT id, is_admin FROM teachers WHERE LOWER(username) = LOWER($1)', [adminUsername]);
    const teacher = result.rows[0];
    if (!teacher) {
      console.warn(`ADMIN_USERNAME "${adminUsername}" not found in database. Register that account first, then restart the server.`);
      return;
    }
    if (!teacher.is_admin) {
      await pool.query('UPDATE teachers SET is_admin = TRUE WHERE id = $1', [teacher.id]);
      console.log(`Granted admin to "${adminUsername}".`);
    } else {
      console.log(`"${adminUsername}" is already an admin.`);
    }
  } catch (error) {
    console.error('Admin bootstrap failed:', error.message);
  }
}

await ensureAdmin();

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`MAACSYS API listening on port ${port}`);
});
