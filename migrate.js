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

pool.query("ALTER TABLE products ADD COLUMN IF NOT EXISTS extra_categories JSONB DEFAULT '[]'")
  .then(() => { console.log('Migration done: extra_categories column added'); process.exit(0); })
  .catch(e => { console.error('Migration failed:', e.message); process.exit(1); });
