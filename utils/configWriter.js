const fs = require('fs');
const path = require('path');
const { uploadToS3, generateS3Key } = require('./s3Upload');

/**
 * Write a config JSON file for a model in the public/configs folder.
 * @param {string} modelName - The model's name (used for filename).
 * @param {object} configObj - The config object to write.
 * @returns {string} The S3 URL to the config file.
 */
async function writeModelConfig(modelName, configObj) {
  // Create temporary file
  const tempDir = path.join(__dirname, '../../temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  // Use timestamp and model name for uniqueness
  const filename = `config-${Date.now()}-${Math.floor(Math.random()*1e8)}-${modelName}.json`;
  const tempFilePath = path.join(tempDir, filename);

  // Write to temporary file
  fs.writeFileSync(tempFilePath, JSON.stringify(configObj, null, 2), 'utf8');

  try {
    // Upload to S3
    const s3Key = generateS3Key('configs', filename);
    const uploadResult = await uploadToS3(tempFilePath, s3Key, 'application/json');

    if (uploadResult.success) {
      console.log(`✅ Config uploaded to S3: ${uploadResult.url}`);
      // Clean up temp file
      fs.unlinkSync(tempFilePath);
      return uploadResult.url;
    } else {
      throw new Error(`Failed to upload config to S3: ${uploadResult.error}`);
    }
  } catch (error) {
    console.error('❌ Error uploading config to S3:', error);
    // Clean up temp file on error
    if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
    }
    throw error;
  }
}

module.exports = { writeModelConfig };
