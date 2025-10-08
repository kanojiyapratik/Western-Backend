const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const MONGODB_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/3dconfigurator';

async function run() {
  await mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');

  // Use the same User model schema as the server (quick minimal model here)
  const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: String,
    permissions: Object,
    // isActive removed
  }, { timestamps: true });

  const User = mongoose.model('UserScriptTemp', UserSchema, 'users'); // use existing 'users' collection

  const email = 'super@gmail.com';
  const rawPassword = '-1234';
  const name = 'Super Admin';

  try {
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    const hashed = await bcrypt.hash(rawPassword, 10);
    const defaultPermissions = {
      // Full model management
      modelUpload: true,
      modelManageUpload: true,
      modelManageEdit: true,
      modelManageDelete: true,
      // UI defaults
      canRotate: true,
      canPan: true,
      canZoom: true,
      saveConfig: true
    };

    if (existing) {
      existing.password = hashed;
      existing.role = 'superadmin';
      existing.name = name;
      existing.permissions = { ...defaultPermissions, ...(existing.permissions || {}) };
      await existing.save();
      console.log('Updated existing superadmin user:', existing.email);
    } else {
      const u = new User({
        name,
        email: email.toLowerCase().trim(),
        password: hashed,
        role: 'superadmin',
        permissions: defaultPermissions
      });
      await u.save();
      console.log('Created superadmin user:', u.email);
    }
  } catch (err) {
    console.error('Error creating/updating superadmin:', err && err.message);
  } finally {
    await mongoose.disconnect();
  }
}

run();
