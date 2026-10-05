'use strict';

// Load environment variables FIRST
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const morgan = require('morgan');
const path = require('path');
const crypto = require('crypto');
const { doubleCsrf } = require('csrf-csrf');

const db = require('./src/db/database');
const { globalLimiter } = require('./src/middleware/rateLimiter');
const { errorHandler } = require('./src/middleware/errorHandler');
const { wafMiddleware } = require('./src/middleware/waf');
const authRoutes = require('./src/routes/auth');
const taskRoutes = require('./src/routes/tasks');
const userRoutes = require('./src/routes/user');
const testBenchRoutes = require('./src/routes/testBench');

// ─── Initialize Database ──────────────────────────────────────────
db.init();

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = process.env.COOKIE_SECURE === 'true' || (isProduction && process.env.FORCE_HTTPS === 'true');

// ─── Trust proxy (for rate limiting behind reverse proxy) ─────────
app.set('trust proxy', 1);

// ─── 1. Helmet — Security Headers (DISABLED FOR SCANNER TESTING) ───
// Intentionally disabled so vulnerability scanners can detect:
// - Missing Content-Security-Policy (CSP)
// - Missing X-Frame-Options (Clickjacking)
// - Missing X-Content-Type-Options (MIME sniffing)
// - Missing Strict-Transport-Security (HSTS)
// - Exposed X-Powered-By: Express header
const enableHelmet = process.env.ENABLE_HELMET === 'true'; // Disabled by default for testing
if (enableHelmet) {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "blob:"],
          connectSrc: ["'self'", "https://*.supabase.co"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
      dnsPrefetchControl: { allow: false },
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
      ieNoOpen: true,
      noSniff: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      xssFilter: true,
    })
  );
} else {
  console.log('[SECURITY] ⚠️  Helmet & Content Security Policy (CSP) DISABLED for scanner verification');
}

// ─── 2. CORS — Restrictive ───────────────────────────────────────
app.use(
  cors({
    origin: false, // Same-origin only
    credentials: true,
  })
);

// ─── 3. HPP — HTTP Parameter Pollution Protection ─────────────────
app.use(hpp());

// ─── 4. Body Parser — Size Limits ─────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ─── 4b. Web Application Firewall (WAF) ───────────────────────────
app.use(wafMiddleware);

// ─── 5. Cookie Parser ─────────────────────────────────────────────
app.use(cookieParser(process.env.CSRF_SECRET));

// ─── 6. Session — Secure Configuration ───────────────────────────
app.use(
  session({
    name: 'sid', // Don't use default 'connect.sid'
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,        // Prevents JavaScript access (XSS protection)
      secure: cookieSecure,  // Adapt for local HTTP or production HTTPS
      sameSite: 'strict',    // CSRF protection
      maxAge: 30 * 60 * 1000, // 30 minutes
      path: '/',
    },
  })
);

// ─── 7. CSRF Protection — Double Submit Cookie ───────────────────
const {
  generateToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: cookieSecure,
    path: '/',
    signed: true,
  },
  size: 64,
  getTokenFromRequest: (req) => {
    return req.headers['x-csrf-token'] || req.body._csrf;
  },
});

// CSRF token endpoint (GET requests are safe, no CSRF needed for this)
app.get('/api/csrf-token', (req, res) => {
  const token = generateToken(req, res);
  res.json({ success: true, token });
});

// Database status endpoint
app.get('/api/db-status', (req, res) => {
  res.json({
    success: true,
    engine: db.activeEngine,
    isSupabase: db.activeEngine === 'supabase',
    supabaseUrl: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.replace(/https?:\/\//, '').split('.')[0] : null,
  });
});

// Apply CSRF protection to all state-changing requests
app.use((req, res, next) => {
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  // Skip CSRF for scanner test-bench if enabled
  if (process.env.ENABLE_TEST_BENCH === 'true' && req.path.startsWith('/api/test-bench')) {
    return next();
  }
  doubleCsrfProtection(req, res, next);
});

// ─── 8. Global Rate Limiter ───────────────────────────────────────
app.use('/api/', (req, res, next) => {
  // Allow high-frequency scanning on test-bench if enabled
  if (process.env.ENABLE_TEST_BENCH === 'true' && req.path.startsWith('/api/test-bench')) {
    return next();
  }
  globalLimiter(req, res, next);
});

// ─── 9. Request Logging (safe — no sensitive data) ─────────────────
app.use(
  morgan(':method :url :status :response-time ms', {
    skip: (req) => req.url === '/favicon.ico',
  })
);

// ─── 10. Static Files — Explicit Directory Only ───────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  etag: true,
  maxAge: isProduction ? '1d' : 0,
  index: 'index.html',
}));

// ─── 11. API Routes ──────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/user', userRoutes);

// Scanner Test Bench (Vulnerability benchmark)
if (process.env.ENABLE_TEST_BENCH === 'true') {
  app.use('/api/test-bench', testBenchRoutes);
}

// ─── 12. Catch-all for SPA routing ──────────────────────────────
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ─── 13. 404 Handler ─────────────────────────────────────────────
app.use((req, res) => {
  // For API routes, return JSON
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ success: false, error: 'Endpoint not found' });
  }
  // For other routes, redirect to index
  res.redirect('/');
});

// ─── 14. Centralized Error Handler ──────────────────────────────
app.use(errorHandler);

// ─── 15. Graceful Shutdown ──────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════╗
║     🛡️  Secure Task Manager — Running            ║
║     Port: ${PORT}                                   ║
║     Env:  ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}                      ║
║                                                  ║
║     Security Features Active:                    ║
║     ✓ Web Application Firewall (WAF Active)      ║
${enableHelmet ? '║     ✓ Helmet (Security Headers + CSP)            ║' : '║     ❌ Helmet / CSP [DISABLED FOR SCANNER]       ║'}
║     ✓ Rate Limiting (Global + Auth)              ║
║     ✓ CSRF Protection (Double Submit)            ║
║     ✓ Session Hardening (httpOnly, Secure)        ║
║     ✓ Input Validation & Sanitization            ║
║     ✓ HPP Protection                             ║
║     ✓ bcrypt Password Hashing (cost 12)          ║
║     ✓ Account Lockout (5 failed = 15min lock)    ║
║     ✓ Request Size Limits (10KB)                 ║
║     ✓ Ownership-Based Access Control             ║
${process.env.ENABLE_TEST_BENCH === 'true' ? '║  ⚠️  SCANNER TEST BENCH ACTIVE (/api/test-bench) ║\n' : ''}╚══════════════════════════════════════════════════╝
  `);
});

process.on('SIGTERM', () => {
  console.log('[SERVER] SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('[SERVER] Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('[SERVER] SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('[SERVER] Server closed');
    process.exit(0);
  });
});

// Prevent unhandled errors from crashing the server
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught Exception:', err.message);
  server.close(() => process.exit(1));
});

process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled Rejection:', reason);
  server.close(() => process.exit(1));
});
