'use strict';

/**
 * Centralized error handler.
 * NEVER exposes stack traces or internal details in production.
 */
function errorHandler(err, req, res, next) {
  // Log the full error server-side for debugging
  console.error('[ERROR]', {
    message: err.message,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    // Only log stack in development
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });

  // CSRF token errors
  if (err.code === 'EBADCSRFTOKEN' || err.message === 'invalid csrf token') {
    return res.status(403).json({
      success: false,
      error: 'Invalid or missing security token. Please refresh the page and try again.',
    });
  }

  // JSON parse errors (malformed request body)
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      error: 'Invalid request format.',
    });
  }

  // Request entity too large
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      error: 'Request body too large.',
    });
  }

  // Default: generic error — no internal details leaked
  const statusCode = err.statusCode || err.status || 500;
  res.status(statusCode).json({
    success: false,
    error: statusCode === 500
      ? 'An unexpected error occurred. Please try again later.'
      : err.message || 'Something went wrong.',
  });
}

module.exports = { errorHandler };
