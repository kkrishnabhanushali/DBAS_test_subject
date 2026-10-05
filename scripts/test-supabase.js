'use strict';

require('dotenv').config();

async function testConnection() {
  console.log('\n🔍 --- Supabase Connection Test ---\n');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey || supabaseUrl.includes('your-project')) {
    console.log('ℹ️  Status: Supabase is NOT currently configured in .env');
    console.log('👉 The app is currently using the built-in local database (data.db.json).');
    console.log('\nTo connect Supabase:');
    console.log('1. Open .env');
    console.log('2. Set SUPABASE_URL=https://<your-project-id>.supabase.co');
    console.log('3. Set SUPABASE_ANON_KEY=<your-anon-key>');
    console.log('4. Run this test again with: node scripts/test-supabase.js\n');
    return;
  }

  console.log(`Connecting to: ${supabaseUrl}...`);

  const headers = {
    'apikey': supabaseKey,
    'Authorization': `Bearer ${supabaseKey}`,
    'Content-Type': 'application/json',
  };

  try {
    // Test users table
    const resUsers = await fetch(`${supabaseUrl}/rest/v1/users?select=count`, {
      method: 'HEAD',
      headers,
    });

    if (resUsers.status === 401 || resUsers.status === 403) {
      console.error('❌ Authentication failed. Check that your SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY is correct.');
      return;
    }

    if (resUsers.status === 404) {
      console.error('⚠️  Connected to Supabase, but the "users" table was not found.');
      console.log('👉 Please open the Supabase SQL Editor and run the SQL from "supabase_schema.sql" to create the tables.');
      return;
    }

    // Test tasks table
    const resTasks = await fetch(`${supabaseUrl}/rest/v1/tasks?select=count`, {
      method: 'HEAD',
      headers,
    });

    if (resTasks.status === 404) {
      console.error('⚠️  The "tasks" table was not found in Supabase.');
      console.log('👉 Please run "supabase_schema.sql" in your Supabase SQL Editor.');
      return;
    }

    console.log('✅ Connection SUCCESSFUL!');
    console.log('✅ Supabase PostgreSQL database is online and reachable.');
    console.log('✅ Required tables (users, tasks) are verified and ready.');
    console.log('\n🎉 SecureTask is fully linked to your Supabase database!\n');
  } catch (err) {
    console.error('❌ Network error while connecting to Supabase:', err.message);
    console.log('Please verify your internet connection and that SUPABASE_URL is accessible.');
  }
}

testConnection();
