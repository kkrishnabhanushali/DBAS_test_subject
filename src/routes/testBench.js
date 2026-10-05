'use strict';

/**
 * ════════════════════════════════════════════════════════════════════
 *  🧪 Scanner Test Bench — Intentional Vulnerability Benchmark
 *  PURPOSE: Used exclusively for verifying DAST / vulnerability scanners.
 *  PROTECTION: Must be explicitly enabled via ENABLE_TEST_BENCH=true
 * ════════════════════════════════════════════════════════════════════
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

/**
 * 1. CWE-79: Reflected Cross-Site Scripting (XSS)
 * Endpoint: GET /api/test-bench/search?q=<payload>
 * Expected Scanner Finding: High / Reflected XSS
 */
router.get('/search', (req, res) => {
  const query = req.query.q || '';
  // Intentionally reflects unsanitized input in HTML content type
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html><html><body><h1>Search Results</h1><p>You searched for: ${query}</p></body></html>`);
});

/**
 * 2. CWE-89: SQL Injection / Injection Simulation
 * Endpoint: GET /api/test-bench/items?id=<payload>
 * Expected Scanner Finding: Critical / SQL Injection
 */
router.get('/items', (req, res) => {
  const id = req.query.id || '';

  // Simulates an unescaped SQL query string vulnerability
  const simulatedQuery = `SELECT * FROM items WHERE item_id = '${id}' AND is_active = 1;`;

  // Simulates SQL error responses when payload includes injection syntax
  if (id.includes("'") || id.toLowerCase().includes('union') || id.includes('--')) {
    return res.status(500).json({
      error: 'Simulated SQL Syntax Error near ' + id,
      executedQuery: simulatedQuery,
      dbEngine: 'PostgreSQL 15.2 (Simulated Test Bed)',
    });
  }

  res.json({
    success: true,
    query: simulatedQuery,
    item: { id, name: 'Sample Item #' + id, inStock: true },
  });
});

/**
 * 3. CWE-22: Path Traversal (Arbitrary File Read)
 * Endpoint: GET /api/test-bench/view-file?file=<payload>
 * Expected Scanner Finding: High / Directory Traversal
 */
router.get('/view-file', (req, res) => {
  const filename = req.query.file;
  if (!filename) {
    return res.status(400).json({ error: 'Parameter "file" required' });
  }

  // Intentionally unsanitized path resolution
  try {
    const targetPath = path.resolve(__dirname, '..', '..', filename);
    if (fs.existsSync(targetPath)) {
      const content = fs.readFileSync(targetPath, 'utf8');
      return res.send(content);
    } else {
      return res.status(404).json({ error: 'File not found', attemptedPath: targetPath });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * 4. CWE-601: Open Redirect
 * Endpoint: GET /api/test-bench/redirect?url=<payload>
 * Expected Scanner Finding: Medium / Open Redirect
 */
router.get('/redirect', (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Parameter "url" required' });
  }
  // Intentionally redirects to any external domain without whitelist validation
  res.redirect(targetUrl);
});

/**
 * 5. CWE-200: Information Exposure (Debug & Environment Leak)
 * Endpoint: GET /api/test-bench/debug-info
 * Expected Scanner Finding: Medium / Sensitive Data Exposure
 */
router.get('/debug-info', (req, res) => {
  res.json({
    status: 'debug_mode_enabled',
    nodeVersion: process.version,
    platform: process.platform,
    serverMemory: process.memoryUsage(),
    serverUptime: process.uptime(),
    simulatedInternalKey: 'TEST_SECRET_API_KEY_4829104812',
    configFiles: ['data.db.json', '.env', 'package.json'],
  });
});

/**
 * 6. CWE-639: Insecure Direct Object Reference (IDOR)
 * Endpoint: GET /api/test-bench/user-record/:id
 * Expected Scanner Finding: High / Broken Object Level Authorization
 */
router.get('/user-record/:id', (req, res) => {
  const requestedId = parseInt(req.params.id, 10);
  // Returns user profile data purely based on the URL parameter without checking auth session
  res.json({
    success: true,
    userRecord: {
      id: requestedId,
      username: `user_${requestedId}`,
      email: `user_${requestedId}@example-corp.internal`,
      accountBalance: 1500 + requestedId * 100,
      role: requestedId === 1 ? 'admin' : 'standard',
    },
  });
});

/**
 * 7. CWE-942: Overly Permissive CORS (Cross-Origin Resource Sharing)
 * Endpoint: OPTIONS & GET /api/test-bench/cors-data
 * Expected Scanner Finding: Low to Medium / Insecure CORS Wildcard with Credentials
 */
router.all('/cors-data', (req, res) => {
  // Reflects origin or wildcards with credentials enabled
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  res.json({
    success: true,
    data: 'Confidential user telemetry',
    echoedOrigin: origin,
  });
});

/**
 * Benchmark Ground Truth Manifest Endpoint
 * Endpoint: GET /api/test-bench/manifest
 */
router.get('/manifest', (req, res) => {
  res.json({
    description: 'Vulnerability Scanner Test Bench Ground Truth Manifest',
    vulnerabilities: [
      {
        cwe: 'CWE-79',
        name: 'Reflected Cross-Site Scripting (XSS)',
        severity: 'High',
        endpoint: '/api/test-bench/search',
        method: 'GET',
        vulnerableParam: 'q',
      },
      {
        cwe: 'CWE-89',
        name: 'SQL Injection Simulation',
        severity: 'Critical',
        endpoint: '/api/test-bench/items',
        method: 'GET',
        vulnerableParam: 'id',
      },
      {
        cwe: 'CWE-22',
        name: 'Directory Traversal',
        severity: 'High',
        endpoint: '/api/test-bench/view-file',
        method: 'GET',
        vulnerableParam: 'file',
      },
      {
        cwe: 'CWE-601',
        name: 'Open Redirect',
        severity: 'Medium',
        endpoint: '/api/test-bench/redirect',
        method: 'GET',
        vulnerableParam: 'url',
      },
      {
        cwe: 'CWE-200',
        name: 'Information Exposure / Debug Endpoint',
        severity: 'Medium',
        endpoint: '/api/test-bench/debug-info',
        method: 'GET',
        vulnerableParam: null,
      },
      {
        cwe: 'CWE-639',
        name: 'Insecure Direct Object Reference (IDOR)',
        severity: 'High',
        endpoint: '/api/test-bench/user-record/:id',
        method: 'GET',
        vulnerableParam: 'id',
      },
      {
        cwe: 'CWE-942',
        name: 'Permissive CORS Configuration',
        severity: 'Medium',
        endpoint: '/api/test-bench/cors-data',
        method: 'GET/OPTIONS',
        vulnerableParam: null,
      },
    ],
  });
});

module.exports = router;
