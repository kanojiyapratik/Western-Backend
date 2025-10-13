// scripts/fix_user_permissions.js
// Run with: node scripts/fix_user_permissions.js
// Fixes all user permissions and roles

const mongoose = require('mongoose');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const User = require('../models/User');

const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/3d-configurator';

// Default permissions for each role
const ROLE_DEFAULT_PERMISSIONS = {
  manager: {
    modelUpload: true,
    modelManageUpload: true,
    modelManageEdit: true,
    modelManageDelete: true,
    userManagement: true,
    userManageCreate: true,
    userManageEdit: true,
    userManageDelete: true,
    doorPresets: true,
    doorToggles: true,
    drawerToggles: true,
    textureWidget: true,
    lightWidget: true,
    globalTextureWidget: true,
    screenshotWidget: true,
    saveConfig: true,
    canRotate: true,
    canPan: true,
    canZoom: true,
    canMove: true,
    reflectionWidget: false,
    movementWidget: false,
    customWidget: false,
    imageDownloadQualities: ['average', 'good', 'best'],
    presetAccess: {},
  },
  employee: {
    modelUpload: false,
    modelManageUpload: false,
    modelManageEdit: false,
    modelManageDelete: false,
    userManagement: false,
    userManageCreate: false,
    userManageEdit: false,
    userManageDelete: false,
    doorPresets: true,
    doorToggles: true,
    drawerToggles: true,
    textureWidget: true,
    lightWidget: true,
    globalTextureWidget: false,
    screenshotWidget: false,
    saveConfig: true,
    canRotate: true,
    canPan: false,
    canZoom: true,
    canMove: false,
    reflectionWidget: false,
    movementWidget: false,
    customWidget: false,
    imageDownloadQualities: ['average'],
    presetAccess: {},
  }
};

async function main() {
  console.log('Connecting to mongo:', MONGO);
  await mongoose.connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true });

  const users = await User.find({});
  console.log(`Found ${users.length} users to fix`);

  for (const user of users) {
    console.log(`\nFixing user: ${user.name} (${user.email})`);
    console.log(`Current role: ${user.role}`);
    
    // Fix role: change "user" to "employee"
    let newRole = user.role;
    if (user.role === 'user') {
      newRole = 'employee';
      console.log(`Changed role from "user" to "employee"`);
    }
    
    // Set correct permissions based on role
    const defaultPerms = ROLE_DEFAULT_PERMISSIONS[newRole] || ROLE_DEFAULT_PERMISSIONS.employee;
    
    // For admin and superadmin, give all permissions
    if (newRole === 'admin' || newRole === 'superadmin') {
      defaultPerms.userManagement = true;
      defaultPerms.userManageCreate = true;
      defaultPerms.userManageEdit = true;
      defaultPerms.userManageDelete = true;
    }
    const newPermissions = {
      ...defaultPerms,
      presetAccess: user.permissions?.presetAccess || {}
    };
    
    console.log(`Setting permissions for role: ${newRole}`);
    
    await User.findByIdAndUpdate(user._id, {
      role: newRole,
      permissions: newPermissions
    });
    
    console.log(`✓ Updated ${user.name}`);
  }

  await mongoose.disconnect();
  console.log('\n✅ All users fixed!');
}

main().catch(err => {
  console.error('Error fixing users:', err);
  process.exit(1);
});