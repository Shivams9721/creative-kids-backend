const { Pool } = require('pg');
require('dotenv').config();

// 1. Get the database link from your environment variables
let dbUrl = process.env.DATABASE_URL || "";

// 2. Forcefully remove the strict SSL command from the URL if it is there
dbUrl = dbUrl.replace("?sslmode=require", "");

// 3. Connect using our custom, AWS-friendly SSL settings
const pool = new Pool({
    connectionString: dbUrl,
    ssl: {
        rejectUnauthorized: false
    }
});

module.exports = pool;