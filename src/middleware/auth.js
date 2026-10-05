'use strict';

/**
 * Authentication middleware — checks if user is logged in via session.
 * Returns generic error to avoid leaking auth state details.
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please log in.',
    });
  }
  next();
}

module.exports = { requireAuth };
