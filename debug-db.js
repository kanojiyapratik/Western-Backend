// Quick database debug script
const mongoose = require('mongoose');
require('dotenv').config();

const User = require('./models/User');

async function debugDatabase() {
  try {
    const MONGODB_URI = process.env.MONGO_URI || "mongodb://localhost:27017/3dconfigurator";
    console.log('🔍 Connecting to:', MONGODB_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@'));
    
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');
    
    const users = await User.find({}).select('name email role');
    console.log('📊 Total users found:', users.length);
    console.log('👥 Users:');
    users.forEach(user => {
      console.log(`  - ${user.email} (${user.name}) [${user.role}]`);
    });
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

debugDatabase();