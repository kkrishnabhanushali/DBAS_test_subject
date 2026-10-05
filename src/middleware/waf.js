'use strict';

/**
 * ════════════════════════════════════════════════════════════════════
 *  🛡️ Web Application Firewall (WAF) Middleware
 *  Inspects incoming requests (URLs, queries, headers, and bodies)
 *  for common web application attack patterns (OWASP Top 10):
 *   - SQL Injection (SQLi)
 *   - Cross-Site Scripting (XSS)
 *   - Path / Directory Traversal (LFI/RFI)
 *   - Remote Code Execution (RCE) / Command Injection
 *   - Prototype Pollution
 *   - Malicious Scanners & User-Agents
 * ════════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

// Attack signature definitions
const WAF_RULES = [
  {
    type: 'SQL_INJECTION',
    description: 'SQL injection payload detected',
    patterns: [
      /\b(union\s+(all\s+)?select)\b/i,
      /\bselect\s+.*?\s+from\b/i,
      /\binsert\s+into\s+.*?\s+values\b/i,
      /\bdelete\s+from\s+\w+/i,
      /\bdrop\s+(table|database|view|index)\b/i,
      /\bexec(\s|\+)+(s|x)p_\w+/i,
      /(?:'|"|`)\s*(?:or|and)\s*(?:'|"|`|\d+)\s*=\s*(?:'|"|`|\d+)/i,
      /\b(benchmark|sleep)\s*\(\s*\d+\s*\)/i,
      /(?:--\s|\/\*[\s\S]*?\*\/|;\s*waitfor\s+delay)/i,
    ],
  },
  {
    type: 'XSS_ATTACK',
    description: 'Cross-Site Scripting (XSS) pattern detected',
    patterns: [
      /<script[\s\S]*?>[\s\S]*?<\/script>/i,
      /<script[\s\S]*?>/i,
      /javascript:\s*[\w(]/i,
      /data:\s*text\/html/i,
      /<\s*img\b[^>]*?\bonerror\s*=/i,
      /<\s*svg\b[^>]*?\bonload\s*=/i,
      /<\s*body\b[^>]*?\bonload\s*=/i,
      /<\s*iframe\b[^>]*?>/i,
      /on(load|error|click|mouseover|focus|blur|submit)\s*=\s*["'][^"']*["']/i,
    ],
  },
  {
    type: 'PATH_TRAVERSAL',
    description: 'Path / directory traversal attempt detected',
    patterns: [
      /(?:\.\.[/\\]){2,}/,
      /\.\.[/\\]/,
      /%2e%2e[%2f%5c]/i,
      /(?:etc\/(?:passwd|shadow|hosts)|boot\.ini|win\.ini|windows[/\\]system32)/i,
      /\/proc\/self\//i,
    ],
  },
  {
    type: 'COMMAND_INJECTION',
    description: 'OS command injection payload detected',
    patterns: [
      /(?:;|\||`|\$\()\s*(?:cat\s+\/etc|whoami|id\b|uname\b|chmod\b|nc\s+-|curl\s+http|wget\s+http)/i,
      /\$\{jndi:(?:ldap|rmi|dns|corba):/i,
      /(?:bin\/(?:sh|bash|zsh|csh))/i,
    ],
  },
  {
    type: 'PROTOTYPE_POLLUTION',
    description: 'Prototype pollution key detected',
    patterns: [
      /__proto__/i,
      /constructor\s*\.\s*prototype/i,
    ],
  },
];

// Malicious scanner / automated bot User-Agent signatures
const SCANNER_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /acunetix/i,
  /nessus/i,
  /masscan/i,
  /zgrab/i,
  /nmap/i,
  /dirbuster/i,
  /gobuster/i,
  /wpscan/i,
  /openvas/i,
  /havij/i,
  /webinspect/i,
];

// Fields excluded from payload string evaluation (e.g., passwords may legitimately have symbols)
const EXCLUDED_FIELDS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'confirmpassword',
  '_csrf',
]);

/**
 * Recursively inspect an object/string for WAF rule violations
 */
function inspectValue(value, keyPath = '') {
  if (value === null || value === undefined) {
    return null;
  }

  // Check prototype pollution on keys
  if (keyPath && (keyPath.includes('__proto__') || keyPath.includes('constructor.prototype'))) {
    return {
      type: 'PROTOTYPE_POLLUTION',
      description: 'Prototype pollution key in parameter name',
      target: keyPath,
      snippet: keyPath,
    };
  }

  // String check
  if (typeof value === 'string') {
    const lowerKey = keyPath.toLowerCase().split('.').pop() || '';
    if (EXCLUDED_FIELDS.has(lowerKey)) {
      return null;
    }

    // Check decoded URI if applicable
    let decodedValue = value;
    try {
      decodedValue = decodeURIComponent(value);
    } catch {
      // keep raw if not valid percent-encoded
    }

    for (const rule of WAF_RULES) {
      for (const pattern of rule.patterns) {
        if (pattern.test(value) || (decodedValue !== value && pattern.test(decodedValue))) {
          return {
            type: rule.type,
            description: rule.description,
            target: keyPath || 'value',
            snippet: value.length > 100 ? value.substring(0, 100) + '...' : value,
          };
        }
      }
    }
    return null;
  }

  // Recursive array / object check
  if (typeof value === 'object') {
    for (const [key, subValue] of Object.entries(value)) {
      const currentPath = keyPath ? `${keyPath}.${key}` : key;
      const hit = inspectValue(subValue, currentPath);
      if (hit) return hit;
    }
  }

  return null;
}

/**
 * WAF Middleware Factory
 */
function createWaf(options = {}) {
  const isEnabled = process.env.WAF_ENABLED !== 'false';
  // Mode: 'block' (default) returns 403, 'monitor' only logs
  const mode = process.env.WAF_MODE || options.mode || 'block';

  return function wafMiddleware(req, res, next) {
    if (!isEnabled) {
      return next();
    }

    // Skip static assets to conserve CPU
    if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/i.test(req.path)) {
      return next();
    }

    // Allow scanner benchmarking on test-bench routes if enabled
    if (process.env.ENABLE_TEST_BENCH === 'true' && req.path.startsWith('/api/test-bench')) {
      return next();
    }

    // 1. Check User-Agent for known malicious scanners
    const userAgent = req.headers['user-agent'] || '';
    for (const scannerPattern of SCANNER_UA_PATTERNS) {
      if (scannerPattern.test(userAgent)) {
        const incidentId = crypto.randomBytes(8).toString('hex');
        console.warn(`[WAF ALERT] [${new Date().toISOString()}] Incident ID: ${incidentId} | IP: ${req.ip} | Malicious scanner detected: ${userAgent}`);
        
        if (mode === 'block') {
          return res.status(403).json({
            success: false,
            error: 'Request blocked by Web Application Firewall (WAF)',
            incidentId,
            reason: 'Automated vulnerability scanner signature detected',
          });
        }
      }
    }

    // 2. Check URL & Path Traversal
    const urlHit = inspectValue(req.originalUrl || req.url, 'url');
    if (urlHit) {
      return triggerWafBlock(req, res, next, urlHit, mode);
    }

    // 3. Check Query Parameters
    if (req.query && Object.keys(req.query).length > 0) {
      const queryHit = inspectValue(req.query, 'query');
      if (queryHit) {
        return triggerWafBlock(req, res, next, queryHit, mode);
      }
    }

    // 4. Check Request Body
    if (req.body && typeof req.body === 'object') {
      const bodyHit = inspectValue(req.body, 'body');
      if (bodyHit) {
        return triggerWafBlock(req, res, next, bodyHit, mode);
      }
    }

    // 5. Check Referer Header
    const referer = req.headers['referer'];
    if (referer) {
      const refererHit = inspectValue(referer, 'header.referer');
      if (refererHit) {
        return triggerWafBlock(req, res, next, refererHit, mode);
      }
    }

    next();
  };
}

function triggerWafBlock(req, res, next, hit, mode) {
  const incidentId = crypto.randomBytes(8).toString('hex');
  const timestamp = new Date().toISOString();

  console.warn(
    `[WAF BLOCKED] [${timestamp}] Incident: ${incidentId} | IP: ${req.ip} | Method: ${req.method} | Path: ${req.path} | Threat: ${hit.type} (${hit.description}) | Target: ${hit.target} | Snippet: "${hit.snippet}"`
  );

  if (mode === 'monitor') {
    // Audit-only mode: add header and continue
    res.setHeader('X-WAF-Warning', `Threat detected: ${hit.type}`);
    return next();
  }

  // Block mode (HTTP 403 Forbidden)
  return res.status(403).json({
    success: false,
    error: 'Request blocked by Web Application Firewall (WAF)',
    incidentId,
    threatType: hit.type,
    message: 'Suspicious payload detected matching known attack patterns.',
  });
}

module.exports = {
  createWaf,
  wafMiddleware: createWaf(),
};
