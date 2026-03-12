module.exports = pool;
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // <-- This is the magic line that fixes the error!
    }
});

module.exports = pool;