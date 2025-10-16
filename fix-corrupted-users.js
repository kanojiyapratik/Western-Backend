// Fix corrupted users with undefined emails
const mongoose = require('mongoose');
require('dotenv').config();

const User = require('./models/User');

async function fixCorruptedUsers() {
  try {
    const MONGODB_URI = process.env.MONGO_URI || "mongodb://localhost:27017/3dconfigurator";
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');
    
    // Find users with undefined/null emails
    const corruptedUsers = await User.find({
      $or: [
        { email: { $exists: false } },
        { email: null },
        { email: undefined },
        { email: "" }
      ]
    });
    
    console.log('🔍 Found corrupted users:', corruptedUsers.length);
    
    if (corruptedUsers.length === 0) {
      console.log('✅ No corrupted users found');
      process.exit(0);
    }
    
    // Show corrupted users
    corruptedUsers.forEach((user, i) => {
      console.log(`${i+1}. ID: ${user._id} | Name: ${user.name} | Email: ${user.email} | Role: ${user.role}`);
    });
    
    // Delete corrupted users
    console.log('\n🗑️ Deleting corrupted users...');
    const result = await User.deleteMany({
      $or: [
        { email: { $exists: false } },
        { email: null },
        { email: undefined },
        { email: "" }
      ]
    });
    
    console.log(`✅ Deleted ${result.deletedCount} corrupted users`);
    
    // Show remaining users
    const remainingUsers = await User.find({}).select('name email role');
    console.log('\n📊 Remaining users:');
    remainingUsers.forEach(user => {
      console.log(`  - ${user.email} (${user.name}) [${user.role}]`);
    });
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

fixCorruptedUsers();