const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const path = require('path');
const fs = require('fs');

// Initialize S3 client
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME;

console.log('🔧 S3 Configuration:', {
  bucket: BUCKET_NAME,
  region: process.env.AWS_REGION,
  accessKey: process.env.AWS_ACCESS_KEY_ID ? 'present' : 'Missing',
  secretKey: process.env.AWS_SECRET_ACCESS_KEY ? 'present' : 'Missing'
});

// Retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 5000,  // 5 seconds
  retryableErrors: [
    'Throttling',
    'ThrottlingException',
    'ProvisionedThroughputExceededException',
    'RequestTimeout',
    'RequestTimeoutException',
    'ServiceUnavailable',
    'InternalError',
    'InternalServerError'
  ]
};

/**
 * Retry function with exponential backoff
 * @param {Function} fn - Function to retry
 * @param {number} maxRetries - Maximum number of retries
 * @param {number} baseDelay - Base delay in milliseconds
 * @param {number} maxDelay - Maximum delay in milliseconds
 * @returns {Promise} - Result of the function
 */
async function retryWithBackoff(fn, maxRetries = RETRY_CONFIG.maxRetries, baseDelay = RETRY_CONFIG.baseDelay, maxDelay = RETRY_CONFIG.maxDelay) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt <= maxRetries && isRetryableError(error)) {
        const delay = Math.min(
          baseDelay * Math.pow(2, attempt - 1) + Math.random() * 1000,
          maxDelay
        );
        
        console.warn(`S3 operation attempt ${attempt} failed, retrying in ${delay}ms:`, error.message);
        await sleep(delay);
        continue;
      }
      
      break;
    }
  }
  
  throw lastError;
}

/**
 * Check if error is retryable
 * @param {Error} error - Error object
 * @returns {boolean} - True if error is retryable
 */
function isRetryableError(error) {
  if (error.name === 'AbortError' || error.code === 'ECONNRESET') {
    return true;
  }
  
  return RETRY_CONFIG.retryableErrors.some(retryableError => 
    error.name === retryableError || 
    error.message.includes(retryableError) ||
    (error.$metadata && error.$metadata.httpStatusCode >= 500)
  );
}

/**
 * Sleep function
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise} - Sleep promise
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validate S3 configuration
 * @throws {Error} - If configuration is invalid
 */
function validateS3Config() {
  if (!BUCKET_NAME) {
    throw new Error('AWS_S3_BUCKET_NAME environment variable is not set');
  }
  
  if (!process.env.AWS_ACCESS_KEY_ID) {
    throw new Error('AWS_ACCESS_KEY_ID environment variable is not set');
  }
  
  if (!process.env.AWS_SECRET_ACCESS_KEY) {
    throw new Error('AWS_SECRET_ACCESS_KEY environment variable is not set');
  }
}

/**
 * Determine content type based on file extension
 * @param {string} filePath - File path
 * @returns {string} - MIME type
 */
function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.glb': 'model/gltf-binary',
    '.gltf': 'model/gltf+json',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.bmp': 'image/bmp',
    '.tiff': 'image/tiff',
    '.webp': 'image/webp',
    '.json': 'application/json',
  };
  return contentTypes[ext] || 'application/octet-stream';
}

/**
 * Upload file to S3 with enhanced error handling and retry logic
 * @param {string} filePath - Local file path
 * @param {string} key - S3 key (path in bucket)
 * @param {string} contentType - MIME type
 * @returns {Promise<{success: boolean, url?: string, key?: string, error?: string}>}
 */
async function uploadToS3(filePath, key, contentType = null) {
  try {
    // Validate configuration
    validateS3Config();
    
    // Validate file exists
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    // Determine content type if not provided
    if (!contentType) {
      contentType = getContentType(filePath);
    }
    
    // Create read stream with error handling
    const fileStream = fs.createReadStream(filePath);
    
    return await retryWithBackoff(async () => {
      // Upload using managed upload for better error handling and progress
      const upload = new Upload({
        client: s3Client,
        params: {
          Bucket: BUCKET_NAME,
          Key: key,
          Body: fileStream,
          ContentType: contentType,
          ACL: 'public-read', // Make files publicly accessible
        },
      });

      const result = await upload.done();

      const url = `https://${BUCKET_NAME}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${key}`;

      console.log(`✅ File uploaded to S3: ${url}`);

      return {
        success: true,
        url: url,
        key: key,
        bucket: BUCKET_NAME,
        etag: result.ETag,
      };
    });
  } catch (error) {
    console.error('❌ S3 upload error:', error);
    
    // Enhanced error categorization
    let errorCode = 'UPLOAD_ERROR';
    let errorMessage = 'File upload failed';
    
    if (error.name === 'AbortError') {
      errorCode = 'UPLOAD_TIMEOUT';
      errorMessage = 'File upload timed out';
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
      errorCode = 'NETWORK_ERROR';
      errorMessage = 'Network error during upload';
    } else if (error.message.includes('access') || error.message.includes('permission')) {
      errorCode = 'AWS_PERMISSION_ERROR';
      errorMessage = 'AWS S3 permission error';
    } else if (error.message.includes('bucket')) {
      errorCode = 'AWS_BUCKET_ERROR';
      errorMessage = 'AWS S3 bucket error';
    }
    
    return {
      success: false,
      error: `${errorCode}: ${errorMessage}`,
      details: error.message,
      retryable: isRetryableError(error)
    };
  }
}

/**
 * Delete file from S3 with retry logic
 * @param {string} key - S3 key to delete
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function deleteFromS3(key) {
  try {
    // Validate configuration
    validateS3Config();
    
    if (!key || typeof key !== 'string') {
      throw new Error('Invalid S3 key provided for deletion');
    }
    
    return await retryWithBackoff(async () => {
      const command = new DeleteObjectCommand({
        Bucket: BUCKET_NAME,
        Key: key,
      });

      await s3Client.send(command);

      console.log(`✅ File deleted from S3: ${key}`);

      return {
        success: true,
      };
    });
  } catch (error) {
    console.error('❌ S3 delete error:', error);
    
    // Enhanced error categorization
    let errorCode = 'DELETE_ERROR';
    let errorMessage = 'File deletion failed';
    
    if (error.name === 'NoSuchKey') {
      errorCode = 'FILE_NOT_FOUND';
      errorMessage = 'File not found in S3';
      return { success: false, error: errorMessage };
    }
    
    return {
      success: false,
      error: `${errorCode}: ${errorMessage}`,
      details: error.message,
      retryable: isRetryableError(error)
    };
  }
}

/**
 * Check if file exists in S3 with error handling
 * @param {string} key - S3 key to check
 * @returns {Promise<boolean>}
 */
async function fileExistsInS3(key) {
  try {
    // Validate configuration
    validateS3Config();
    
    if (!key || typeof key !== 'string') {
      return false;
    }

    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
    });

    await s3Client.send(command);
    return true;

  } catch (error) {
    if (error.name === 'NoSuchKey' || error.name === 'NotFound') {
      return false;
    }
    console.error('❌ S3 exists check error:', error);
    return false;
  }
}

/**
 * Generate S3 key for file upload
 * @param {string} folder - Folder name (e.g., 'models', 'textures', 'preset-images')
 * @param {string} filename - Original filename
 * @returns {string} - Generated S3 key
 */
function generateS3Key(folder, filename) {
  const timestamp = Date.now();
  const random = Math.round(Math.random() * 1E9);
  const ext = path.extname(filename);
  const basename = path.basename(filename, ext);

  return `${folder}/${basename}_${timestamp}_${random}${ext}`;
}

/**
 * Upload multiple files to S3
 * @param {Array} files - Array of { filePath, key, contentType }
 * @returns {Promise<Array>} - Results for each file
 */
async function uploadMultipleFiles(files) {
  const results = [];
  
  for (const file of files) {
    try {
      const result = await uploadToS3(file.filePath, file.key, file.contentType);
      results.push({ ...file, ...result });
    } catch (error) {
      results.push({ 
        ...file, 
        success: false, 
        error: error.message 
      });
    }
  }
  
  return results;
}

module.exports = {
  uploadToS3,
  deleteFromS3,
  fileExistsInS3,
  generateS3Key,
  uploadMultipleFiles,
  retryWithBackoff,
  s3Client,
  BUCKET_NAME,
};