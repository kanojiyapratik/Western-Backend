// scripts/create_demo_users.js
// Run with: node scripts/create_demo_users.js
// Creates demo users: user, admin, superadmin if they don't exist

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const User = require('../models/User');

const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/3d-configurator';

async function main() {
  console.log('Connecting to mongo:', MONGO);
  await mongoose.connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true });

  const demoUsers = [
    { name: 'Demo User', email: 'user@example.com', password: 'user123', role: 'user' },
    { name: 'Demo Admin', email: 'admin@example.com', password: 'admin123', role: 'admin', adminQuota: 10 },
    { name: 'Demo SuperAdmin', email: 'superadmin@example.com', password: 'superadmin123', role: 'superadmin' }
  ];

  for (const u of demoUsers) {
    const existing = await User.findOne({ email: u.email });
    if (existing) {
      console.log(`Skipping ${u.email} (already exists)`);
      continue;
    }

    const hashed = await bcrypt.hash(u.password, 10);
    const user = new User({
      name: u.name,
      email: u.email,
      password: hashed,
      role: u.role,
      isActive: true,
      adminQuota: u.adminQuota || null,
      usersCreatedCount: 0
    });

    await user.save();
    console.log(`Created ${u.email} (${u.role})`);
  }

  await mongoose.disconnect();
  console.log('Done');
}

main().catch(err => {
  console.error('Error creating demo users', err);
  process.exit(1);
});
