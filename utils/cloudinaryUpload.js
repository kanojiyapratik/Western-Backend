const cloudinary = require('cloudinary').v2;
const fs = require('fs');

// Upload file to Cloudinary
const uploadToCloudinary = async (filePath, options = {}) => {
  try {
    console.log(`Starting Cloudinary upload for file: ${filePath}`);

    // Check file size first
    const fs = require('fs');
    const stats = fs.statSync(filePath);
    const fileSizeMB = stats.size / (1024 * 1024);
    console.log(`File size: ${fileSizeMB.toFixed(2)} MB`);

    // For very large files, use different strategy
    const uploadOptions = {
      resource_type: 'auto',
      folder: options.folder || 'models',
      public_id: options.public_id,
      ...options
    };

    if (fileSizeMB > 50) {
      // For files over 50MB, use raw resource type and extended settings
      uploadOptions.resource_type = 'raw';
      uploadOptions.timeout = 1200000; // 20 minutes for very large files
      uploadOptions.chunk_size = 1000000; // 1MB chunks for stability
      console.log(`Using extended settings for large file:`, uploadOptions);
    } else if (fileSizeMB > 10) {
      // For files 10-50MB
      uploadOptions.timeout = 900000; // 15 minutes
      uploadOptions.chunk_size = 2000000; // 2MB chunks
      console.log(`Using extended settings for medium-large file:`, uploadOptions);
    } else {
      // For smaller files
      uploadOptions.timeout = 300000; // 5 minutes
      uploadOptions.chunk_size = 6000000; // 6MB chunks
      console.log(`Using standard settings for smaller file:`, uploadOptions);
    }

    const result = await cloudinary.uploader.upload(filePath, uploadOptions);

    console.log(`Cloudinary upload successful: ${result.public_id} (${(result.bytes / (1024 * 1024)).toFixed(2)} MB)`);
    
    // Delete local file after successful upload
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log(`Local file deleted: ${filePath}`);
    } else {
      console.log(`Local file not found for deletion: ${filePath}`);
    }
    
    return {
      success: true,
      url: result.secure_url,
      public_id: result.public_id,
      resource_type: result.resource_type,
      format: result.format,
      bytes: result.bytes
    };
  } catch (error) {
    console.error('Cloudinary upload error:', error);
    return {
      success: false,
      error: error.message || error.error?.message || 'Upload failed'
    };
  }
};

// Delete file from Cloudinary
const deleteFromCloudinary = async (public_id, resource_type = 'raw') => {
  try {
    console.log(`Attempting to delete from Cloudinary: ${public_id} (type: ${resource_type})`);
    const result = await cloudinary.uploader.destroy(public_id, {
      resource_type
    });
    console.log('Cloudinary delete result:', result);
    return {
      success: result.result === 'ok',
      result,
      error: result.result !== 'ok' ? `Delete failed: ${result.result}` : null
    };
  } catch (error) {
    console.error('Cloudinary delete error:', error);
    return {
      success: false,
      error: error.message || 'Unknown error'
    };
  }
};

module.exports = {
  uploadToCloudinary,
  deleteFromCloudinary
};