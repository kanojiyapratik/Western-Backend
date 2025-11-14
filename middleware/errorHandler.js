/**
 * Centralized Error Handling Middleware
 * Provides standardized error responses and logging
 */

const errorHandler = (err, req, res, next) => {
  // Default error response
  let error = {
    success: false,
    error: {
      code: 'UNKNOWN_ERROR',
      message: 'An unexpected error occurred',
      timestamp: new Date().toISOString(),
      path: req.path,
      method: req.method
    }
  };

  // Handle specific error types
  if (err.name === 'ValidationError') {
    error.error.code = 'VALIDATION_ERROR';
    error.error.message = 'Data validation failed';
    error.error.details = err.details || err.message;
    return res.status(400).json(error);
  }

  if (err.name === 'CastError') {
    error.error.code = 'INVALID_ID';
    error.error.message = 'Invalid ID format';
    return res.status(400).json(error);
  }

  if (err.name === 'MongoError' && err.code === 11000) {
    error.error.code = 'DUPLICATE_ENTRY';
    error.error.message = 'Duplicate entry found';
    error.error.details = err.keyValue;
    return res.status(409).json(error);
  }

  if (err.name === 'JsonWebTokenError') {
    error.error.code = 'INVALID_TOKEN';
    error.error.message = 'Invalid authentication token';
    return res.status(401).json(error);
  }

  if (err.name === 'TokenExpiredError') {
    error.error.code = 'TOKEN_EXPIRED';
    error.error.message = 'Authentication token has expired';
    return res.status(401).json(error);
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    error.error.code = 'FILE_TOO_LARGE';
    error.error.message = 'Uploaded file exceeds size limit';
    return res.status(413).json(error);
  }

  if (err.code === 'ENOENT') {
    error.error.code = 'FILE_NOT_FOUND';
    error.error.message = 'Required file not found';
    return res.status(404).json(error);
  }

  // Handle multer errors
  if (err.code && err.code.startsWith('LIMIT_')) {
    const errorMap = {
      'LIMIT_FILE_SIZE': 'File size exceeds limit',
      'LIMIT_FILE_COUNT': 'Too many files uploaded',
      'LIMIT_UNEXPECTED_FILE': 'Unexpected file field'
    };
    error.error.code = 'FILE_UPLOAD_ERROR';
    error.error.message = errorMap[err.code] || 'File upload error';
    return res.status(400).json(error);
  }

  // Handle AWS S3 errors
  if (err.code && err.code.startsWith('AWS')) {
    error.error.code = 'AWS_ERROR';
    error.error.message = 'Cloud storage operation failed';
    error.error.details = err.message;
    return res.status(500).json(error);
  }

  // Handle email errors
  if (err.message && err.message.includes('email')) {
    error.error.code = 'EMAIL_ERROR';
    error.error.message = 'Email operation failed';
    error.error.details = err.message;
    return res.status(500).json(error);
  }

  // Handle database connection errors
  if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
    error.error.code = 'DATABASE_ERROR';
    error.error.message = 'Database connection failed';
    return res.status(503).json(error);
  }

  // Set status code based on error
  if (err.status) {
    error.error.code = err.code || error.error.code;
    error.error.message = err.message;
    error.status = err.status;
  }

  // Log error for debugging (only in development)
  if (process.env.NODE_ENV !== 'production') {
    console.error('Error Handler:', {
      error: err,
      stack: err.stack,
      request: {
        method: req.method,
        url: req.url,
        body: req.body,
        params: req.params,
        query: req.query
      }
    });
  }

  // Send appropriate status code
  const statusCode = error.status || 500;
  return res.status(statusCode).json(error);
};

module.exports = errorHandler;