// scripts/fix_superadmin_password.js
// Fixes the superadmin password by setting it to a plain value and relying on pre-save hook to hash it once.

const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const User = require('../models/User');

const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/3dconfigurator';

async function main() {
  console.log('Connecting to mongo:', MONGO);
  await mongoose.connect(MONGO);

  const email = 'superadmin@example.com';
  const user = await User.findOne({ email });
  if (!user) {
    console.log('Superadmin not found');
    await mongoose.disconnect();
    return;
  }

  user.password = 'superadmin123';
  await user.save();
  console.log('Updated password for', email);

  await mongoose.disconnect();
}

main().catch(err => {
  console.error('Error fixing password', err);
  process.exit(1);
});
