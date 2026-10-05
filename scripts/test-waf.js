'use strict';

/**
 * ════════════════════════════════════════════════════════════════════
 *  🛡️ WAF (Web Application Firewall) Test Script
 *  Tests the application against simulated OWASP attack vectors:
 *   1. SQL Injection (SQLi)
 *   2. Cross-Site Scripting (XSS)
 *   3. Path Traversal
 *   4. Malicious Scanner User-Agent (sqlmap)
 *   5. Prototype Pollution
 *   6. Legitimate Request (Should pass)
 * ════════════════════════════════════════════════════════════════════
 */

const http = require('http');

const PORT = process.env.PORT || 3000;
const BASE_URL = `http://localhost:${PORT}`;

function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body ? safeJsonParse(body) : null,
        });
      });
    });

    req.on('error', (err) => reject(err));

    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

async function runTests() {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║     🛡️  Testing Web Application Firewall (WAF)   ║');
  console.log(`║     Target: ${BASE_URL.padEnd(36)} ║`);
  console.log('╚══════════════════════════════════════════════════╝\n');

  const tests = [
    {
      name: 'SQL Injection in Query String',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token?category=1%27%20UNION%20SELECT%20*%20FROM%20users--',
        method: 'GET',
      },
      expectedStatus: 403,
      expectedThreat: 'SQL_INJECTION',
    },
    {
      name: 'Cross-Site Scripting (XSS) in Request Body',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      },
      postData: {
        payload: '<script>alert("XSS")</script>',
      },
      expectedStatus: 403,
      expectedThreat: 'XSS_ATTACK',
    },
    {
      name: 'Path Traversal attempt in URL',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token/../../etc/passwd',
        method: 'GET',
      },
      expectedStatus: 403,
      expectedThreat: 'PATH_TRAVERSAL',
    },
    {
      name: 'Malicious Scanner User-Agent (sqlmap)',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token',
        method: 'GET',
        headers: {
          'User-Agent': 'sqlmap/1.6.12#stable (https://sqlmap.org)',
        },
      },
      expectedStatus: 403,
      expectedReason: 'Automated vulnerability scanner signature detected',
    },
    {
      name: 'Prototype Pollution in JSON Body',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      },
      postData: {
        '__proto__': { 'isAdmin': true },
      },
      expectedStatus: 403,
      expectedThreat: 'PROTOTYPE_POLLUTION',
    },
    {
      name: 'Legitimate Safe Request (Should PASS)',
      options: {
        hostname: 'localhost',
        port: PORT,
        path: '/api/csrf-token',
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        },
      },
      expectedStatus: 200,
    },
  ];

  let passed = 0;

  for (const test of tests) {
    try {
      const res = await makeRequest(test.options, test.postData);
      const isStatusMatch = res.statusCode === test.expectedStatus;
      
      let isThreatMatch = true;
      if (test.expectedThreat && res.body && res.body.threatType !== test.expectedThreat) {
        isThreatMatch = false;
      }

      if (isStatusMatch && isThreatMatch) {
        console.log(`✅ PASS: ${test.name}`);
        if (test.expectedStatus === 403) {
          console.log(`   └─ Blocked with 403 Forbidden | Threat: ${res.body?.threatType || res.body?.reason || 'Blocked'}`);
        } else {
          console.log(`   └─ Allowed with ${res.statusCode} OK`);
        }
        passed++;
      } else {
        console.log(`❌ FAIL: ${test.name}`);
        console.log(`   Expected ${test.expectedStatus}, got ${res.statusCode}`);
        console.log(`   Response:`, res.body);
      }
    } catch (err) {
      console.log(`❌ ERROR on "${test.name}":`, err.message);
    }
  }

  console.log(`\n══════════════════════════════════════════════════`);
  console.log(` Results: ${passed}/${tests.length} tests passed`);
  console.log(`══════════════════════════════════════════════════\n`);
}

runTests();
