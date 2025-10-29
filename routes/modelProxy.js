const express = require('express');
const router = express.Router();
const axios = require('axios');
const { BUCKET_NAME } = require('../utils/s3Upload');

// Proxy GLB files to avoid CORS issues
router.get('/glb/:key(*)', async (req, res) => {
  try {
    const key = req.params.key;
    const s3Url = `https://${BUCKET_NAME}.s3.ap-south-1.amazonaws.com/${key}`;

    console.log('📁 Proxying GLB file:', s3Url);

    // Fetch the file from S3
    const response = await axios.get(s3Url, {
      responseType: 'stream',
      timeout: 30000, // 30 second timeout
    });

    // Set appropriate headers
    res.setHeader('Content-Type', 'model/gltf-binary');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour

    // Pipe the response
    response.data.pipe(res);

  } catch (error) {
    console.error('❌ Error proxying GLB file:', error.message);
    res.status(404).json({ error: 'Model not found' });
  }
});

module.exports = router;