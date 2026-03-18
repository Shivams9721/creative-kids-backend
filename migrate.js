require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  database: process.env.PG_DATABASE,
  ssl: process.env.PG_HOST === 'localhost' ? false : { rejectUnauthorized: false }
});

const migrations = [
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS extra_categories JSONB DEFAULT '[]'",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS color_images JSONB DEFAULT '{}'",
  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS coupons (
    id SERIAL PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    discount_type TEXT NOT NULL CHECK (discount_type IN ('percent','flat')),
    discount_value NUMERIC NOT NULL,
    min_order_amount NUMERIC DEFAULT 0,
    max_uses INTEGER DEFAULT NULL,
    uses INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ DEFAULT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`,
];

(async () => {
  for (const sql of migrations) {
    try {
      await pool.query(sql);
      console.log('✓', sql.slice(0, 60).replace(/\n/g, ' '));
    } catch (e) {
      console.error('✗', e.message);
    }
  }
  await pool.end();
  console.log('All migrations complete.');
})();
