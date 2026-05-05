/**
 * System-wide Custom Error Classes
 * Used to provide consistent status codes and messages across the API.
 */

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * 401 Unauthorized - Used when credentials or tokens are invalid
 */
class AuthenticationError extends AppError {
  constructor(message = "Authentication failed") {
    super(message, 401);
  }
}

/**
 * 403 Forbidden - Used when a user lacks required permissions
 */
class ForbiddenError extends AppError {
  constructor(message = "Access denied") {
    super(message, 403);
  }
}

/**
 * 404 Not Found - Used when a user or resource does not exist
 */
class NotFoundError extends AppError {
  constructor(message = "Resource not found") {
    super(message, 404);
  }
}

/**
 * 429 Too Many Requests - Used for throttling and security blocks
 */
class RateLimitError extends AppError {
  constructor(message = "Too many attempts", retryAfterSeconds = null) {
    super(message, 429);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * 400 Bad Request - Used for input validation failures
 */
class ValidationError extends AppError {
  constructor(message = "Invalid input data") {
    super(message, 400);
  }
}

module.exports = {
  AppError,
  AuthenticationError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  ValidationError
};
