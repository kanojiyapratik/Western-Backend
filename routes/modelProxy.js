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
      timeout: 60000, // 60 second timeout for production
      headers: {
        'User-Agent': '3D-Configurator-Proxy/1.0'
      }
    });

    // Set appropriate headers
    res.setHeader('Content-Type', 'model/gltf-binary');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Pipe the response
    response.data.pipe(res);

  } catch (error) {
    console.error('❌ Error proxying GLB file:', error.message);
    console.error('❌ Error details:', error.response?.status, error.response?.statusText);
    res.status(404).json({ error: 'Model not found', details: error.message });
  }
});

// Proxy thumbnail images to avoid CORS issues
router.get('/thumbnail/:key(*)', async (req, res) => {
  try {
    const key = req.params.key;
    const s3Url = `https://${BUCKET_NAME}.s3.ap-south-1.amazonaws.com/${key}`;

    console.log('🖼️ Proxying thumbnail:', s3Url);

    // Fetch the image from S3
    const response = await axios.get(s3Url, {
      responseType: 'stream',
      timeout: 30000, // 30 second timeout for images
      headers: {
        'User-Agent': '3D-Configurator-Proxy/1.0'
      }
    });

    // Set appropriate headers for images
    res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Pipe the response
    response.data.pipe(res);

  } catch (error) {
    console.error('❌ Error proxying thumbnail:', error.message);
    console.error('❌ Error details:', error.response?.status, error.response?.statusText);
    res.status(404).json({ error: 'Thumbnail not found', details: error.message });
  }
});

module.exports = router;