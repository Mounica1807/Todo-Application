require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function testConnection() {
  try {
    const client = await pool.connect();
    console.log('✅ Successfully connected to Neon database!');
    const res = await client.query('SELECT NOW()');
    console.log('Current time from DB:', res.rows[0].now);
    client.release();
  } catch (err) {
    console.error('❌ Connection failed:', err.message);
    if (err.code) console.error('Error code:', err.code);
    if (err.stack) console.error('Full stack:', err.stack);
  } finally {
    await pool.end();
  }
}

testConnection();