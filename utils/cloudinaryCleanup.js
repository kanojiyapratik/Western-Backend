const cloudinary = require('cloudinary').v2;

// Get all files in Cloudinary models folder
const getCloudinaryFiles = async () => {
  try {
    const result = await cloudinary.api.resources({
      type: 'upload',
      prefix: 'models/',
      max_results: 500
    });
    return result.resources;
  } catch (error) {
    console.error('Error fetching Cloudinary files:', error);
    return [];
  }
};

// Delete specific file from Cloudinary
const deleteCloudinaryFile = async (public_id) => {
  try {
    const result = await cloudinary.uploader.destroy(public_id);
    return { success: result.result === 'ok', result };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Clean up orphaned files (files in Cloudinary but not in database)
const cleanupOrphanedFiles = async (Model) => {
  try {
    const cloudinaryFiles = await getCloudinaryFiles();
    const dbModels = await Model.find({}).select('file path assets');
    
    const dbFileIds = new Set();
    
    // Collect all file IDs from database
    dbModels.forEach(model => {
      if (model.file) dbFileIds.add(model.file);
      if (model.assets) {
        Object.values(model.assets).forEach(url => {
          if (url && url.includes('cloudinary.com')) {
            const urlParts = url.split('/');
            const publicId = urlParts[urlParts.length - 1].split('.')[0];
            dbFileIds.add(`models/${publicId}`);
          }
        });
      }
    });
    
    const orphanedFiles = cloudinaryFiles.filter(file => !dbFileIds.has(file.public_id));
    
    const report = { deleted: [], errors: [], orphaned: orphanedFiles.length };
    
    for (const file of orphanedFiles) {
      const deleteResult = await deleteCloudinaryFile(file.public_id);
      if (deleteResult.success) {
        report.deleted.push(file.public_id);
      } else {
        report.errors.push(`Failed to delete ${file.public_id}: ${deleteResult.error}`);
      }
    }
    
    return report;
  } catch (error) {
    return { error: error.message };
  }
};

module.exports = {
  getCloudinaryFiles,
  deleteCloudinaryFile,
  cleanupOrphanedFiles
};