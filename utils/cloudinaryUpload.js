const cloudinary = require('cloudinary').v2;
const fs = require('fs');

// Upload file to Cloudinary
const uploadToCloudinary = async (filePath, options = {}) => {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      resource_type: 'auto', // Automatically detect file type
      folder: options.folder || 'models', // Default folder
      public_id: options.public_id, // Optional custom public ID
      timeout: 120000, // 2 minutes timeout
      ...options
    });
    
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