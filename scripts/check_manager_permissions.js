const mongoose = require('mongoose');
const User = require('../models/User');

async function checkManagerPermissions() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect('mongodb://localhost:27017/3dconfigurator');
    console.log('Connected to MongoDB');
    
    // Check total user count first
    const userCount = await User.countDocuments();
    console.log(`Total users in database: ${userCount}`);
    
    // Find all users
    const allUsers = await User.find({}).select('-password');
    console.log(`Found ${allUsers.length} users`);
    
    console.log('=== ALL USERS ===');
    if (allUsers.length === 0) {
      console.log('No users found in database');
    } else {
      allUsers.forEach(user => {
        console.log(`\nUser: ${user.name} (${user.email})`);
        console.log(`Role: ${user.role}`);
        console.log(`Permissions:`, JSON.stringify(user.permissions, null, 2));
        console.log(`userManagement permission:`, user.permissions?.userManagement);
      });
    }
    
    // Find users with manager role specifically
    const managers = allUsers.filter(user => user.role === 'manager');
    console.log(`\n=== MANAGER COUNT: ${managers.length} ===`);
    
    // Find users with userManagement permission
    const usersWithUserMgmt = allUsers.filter(user => user.permissions?.userManagement === true);
    console.log(`=== USERS WITH userManagement PERMISSION: ${usersWithUserMgmt.length} ===`);
    usersWithUserMgmt.forEach(user => {
      console.log(`- ${user.name} (${user.role})`);
    });
    
    mongoose.connection.close();
  } catch (error) {
    console.error('Error:', error);
    mongoose.connection.close();
  }
}

checkManagerPermissions();