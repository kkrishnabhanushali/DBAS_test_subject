'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimiter');
const { validateUpdateProfile, validateChangePassword } = require('../middleware/validator');

const BCRYPT_ROUNDS = 12;

// All user routes require authentication
router.use(requireAuth);
router.use(apiLimiter);

/**
 * GET /api/user/profile
 * Get current user's profile
 */
router.get('/profile', async (req, res, next) => {
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

/**
 * PUT /api/user/profile
 * Update profile (validated + field whitelist)
 */
router.put('/profile', validateUpdateProfile, async (req, res, next) => {
  try {
    // Explicit field whitelist
    const { displayName, email } = req.body;
    const user = await db.updateUser(req.session.userId, { displayName, email });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, user, message: 'Profile updated' });
  } catch (err) {
    if (err.message === 'EMAIL_EXISTS') {
      return res.status(409).json({
        success: false,
        error: 'That email is already in use.',
      });
    }
    next(err);
  }
});

/**
 * PUT /api/user/password
 * Change password (requires current password verification)
 */
router.put('/password', validateChangePassword, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password hash
    const user = await db.findUserByIdWithPassword(req.session.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect.',
      });
    }

    // Hash and update new password
    const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await db.updateUserPassword(req.session.userId, newHash);

    // Regenerate session after password change
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.save((err) => {
        if (err) return next(err);
        res.json({ success: true, message: 'Password changed successfully' });
      });
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
