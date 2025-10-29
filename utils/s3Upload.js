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

/**
 * Upload file to S3
 * @param {string} filePath - Local file path
 * @param {string} key - S3 key (path in bucket)
 * @param {string} contentType - MIME type
 * @returns {Promise<{success: boolean, url?: string, key?: string, error?: string}>}
 */
async function uploadToS3(filePath, key, contentType = null) {
  try {
    if (!BUCKET_NAME) {
      throw new Error('AWS_S3_BUCKET_NAME environment variable is not set');
    }

    // Determine content type if not provided
    if (!contentType) {
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
      contentType = contentTypes[ext] || 'application/octet-stream';
    }

    // Create read stream
    const fileStream = fs.createReadStream(filePath);
    fileStream.on('error', (err) => {
      console.error('File stream error:', err);
      throw err;
    });

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

  } catch (error) {
    console.error('❌ S3 upload error:', error);
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Delete file from S3
 * @param {string} key - S3 key to delete
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function deleteFromS3(key) {
  try {
    if (!BUCKET_NAME) {
      throw new Error('AWS_S3_BUCKET_NAME environment variable is not set');
    }

    const command = new DeleteObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
    });

    await s3Client.send(command);

    console.log(`✅ File deleted from S3: ${key}`);

    return {
      success: true,
    };

  } catch (error) {
    console.error('❌ S3 delete error:', error);
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Check if file exists in S3
 * @param {string} key - S3 key to check
 * @returns {Promise<boolean>}
 */
async function fileExistsInS3(key) {
  try {
    if (!BUCKET_NAME) {
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

module.exports = {
  uploadToS3,
  deleteFromS3,
  fileExistsInS3,
  generateS3Key,
  s3Client,
  BUCKET_NAME,
};