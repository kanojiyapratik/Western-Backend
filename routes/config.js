const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// GET /api/configs/:filename - Read a config file
router.get('/:filename', async (req, res, next) => {
  try {
    const { filename } = req.params;
    if (!filename.endsWith('.json')) return next();
    const configsDir = path.join(__dirname, '../../Frontend/public/configs');
    const filePath = path.join(configsDir, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'Config file not found' });
    const content = fs.readFileSync(filePath, 'utf8');
    const json = JSON.parse(content);
    res.json(json);
  } catch (err) {
    res.status(500).json({ message: 'Failed to read config', error: err.message });
  }
});

// PUT /api/configs/:filename - Overwrite an existing config file
router.put('/:filename', async (req, res, next) => {
  try {
    const { filename } = req.params;
    if (!filename.endsWith('.json')) return next();
    const configsDir = path.join(__dirname, '../../Frontend/public/configs');
    const filePath = path.join(configsDir, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'Config file not found' });
    fs.writeFileSync(filePath, JSON.stringify(req.body, null, 2), 'utf8');
    res.json({ message: 'Config updated', path: `/configs/${filename}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update config', error: err.message });
  }
});

// DELETE /api/configs/:filename - Remove a config file
router.delete('/:filename', async (req, res, next) => {
  try {
    const { filename } = req.params;
    if (!filename.endsWith('.json')) return next();
    const configsDir = path.join(__dirname, '../../Frontend/public/configs');
    const filePath = path.join(configsDir, filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'Config file not found' });
    fs.unlinkSync(filePath);
    res.json({ message: 'Config deleted', path: `/configs/${filename}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete config', error: err.message });
  }
});

module.exports = router;
