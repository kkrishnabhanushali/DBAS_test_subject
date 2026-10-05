'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('../db/database');
const { authLimiter } = require('../middleware/rateLimiter');
const { validateRegister, validateLogin } = require('../middleware/validator');
const { requireAuth } = require('../middleware/auth');

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;

/**
 * POST /api/auth/register
 * Rate limited + validated + hashed password
 */
router.post('/register', authLimiter, validateRegister, async (req, res, next) => {
  try {
    const { username, email, password, displayName } = req.body;

    // Hash password with bcrypt (cost factor 12)
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const userId = await db.createUser({
      username,
      email,
      passwordHash,
      displayName,
    });

    // Create session immediately after registration
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = userId;
      req.session.username = username;
      req.session.save((err) => {
        if (err) return next(err);
        res.status(201).json({
          success: true,
          message: 'Account created successfully',
          user: { id: userId, username, email, displayName },
        });
      });
    });
  } catch (err) {
    if (err.message === 'USERNAME_EXISTS') {
      return res.status(409).json({
        success: false,
        error: 'An account with that username already exists.',
      });
    }
    if (err.message === 'EMAIL_EXISTS') {
      return res.status(409).json({
        success: false,
        error: 'An account with that email already exists.',
      });
    }
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Rate limited + validated + account lockout + timing-safe comparison
 */
router.post('/login', authLimiter, validateLogin, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    // Check IP-based failed attempts
    const ipAttempts = await db.getRecentFailedAttempts(ip);
    if (ipAttempts >= MAX_FAILED_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        error: 'Too many failed login attempts. Please try again in 15 minutes.',
      });
    }

    // Find user
    const user = await db.findUserByUsername(username);

    // Generic error for both wrong username and wrong password
    // Prevents username enumeration
    const genericError = 'Invalid username or password.';

    if (!user) {
      // Still hash to prevent timing attacks (constant time even if user doesn't exist)
      await bcrypt.hash('dummy-password', BCRYPT_ROUNDS);
      await db.recordLoginAttempt(ip, username, false);
      return res.status(401).json({ success: false, error: genericError });
    }

    // Check if account is locked
    if (user.isLocked) {
      if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
        await db.recordLoginAttempt(ip, username, false);
        return res.status(423).json({
          success: false,
          error: 'Account is temporarily locked due to too many failed attempts. Try again in 15 minutes.',
        });
      }
      // Unlock if lock has expired
      user.isLocked = false;
      user.lockedUntil = null;
    }

    // Compare password (bcrypt is timing-safe)
    const isValid = await bcrypt.compare(password, user.passwordHash);

    if (!isValid) {
      await db.recordLoginAttempt(ip, username, false);

      // Check if should lock account
      const userAttempts = await db.getRecentFailedAttemptsByUsername(username);
      if (userAttempts >= MAX_FAILED_ATTEMPTS) {
        await db.lockUser(username);
        return res.status(423).json({
          success: false,
          error: 'Account locked due to too many failed attempts. Try again in 15 minutes.',
        });
      }

      return res.status(401).json({ success: false, error: genericError });
    }

    // Successful login — record and regenerate session
    await db.recordLoginAttempt(ip, username, true);

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.save((err) => {
        if (err) return next(err);
        res.json({
          success: true,
          message: 'Login successful',
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
          },
        });
      });
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/logout
 * Destroys session completely
 */
router.post('/logout', requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid', { path: '/' });
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

/**
 * GET /api/auth/me
 * Returns current user info if authenticated
 */
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await db.findUserById(req.session.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
