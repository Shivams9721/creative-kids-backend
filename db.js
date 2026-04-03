const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// 1. Safely grab the URL from AWS
let connectionString = process.env.DATABASE_URL || "";
connectionString = connectionString.replace("?sslmode=require", "");

// 2. Configure the Professional Connection Pool
const pool = new Pool({
    connectionString: connectionString,
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync(path.join(__dirname, 'certs', 'global-bundle.pem')).toString(),
    },
    
    // --- SECURITY & PERFORMANCE SAFEGUARDS ---
    max: 20,                      // Maximum number of simultaneous connections allowed
    idleTimeoutMillis: 30000,     // Close connections automatically after 30 seconds of inactivity
    connectionTimeoutMillis: 5000 // If DB doesn't respond in 5 seconds, fail gracefully instead of freezing
});

// 3. Secure Error Handling (Prevents sensitive data leaks)
pool.on('error', (err, client) => {
    // We only log the safe message, NOT the full error object which might contain passwords
    console.error('❌ Database connection error on idle client:', err.message);
});

module.exports = pool;