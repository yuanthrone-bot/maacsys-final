CREATE TABLE IF NOT EXISTS teachers (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  cell TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  verification_code TEXT,
  verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);
