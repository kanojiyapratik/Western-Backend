// Fix duplicate users script
const mongoose = require('mongoose');
require('dotenv').config();

const User = require('./models/User');

async function fixDuplicates() {
  try {
    const MONGODB_URI = process.env.MONGO_URI || "mongodb://localhost:27017/3dconfigurator";
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');
    
    // Find all users
    const users = await User.find({}).sort({ createdAt: 1 });
    console.log('📊 Total users:', users.length);
    
    // Group by email
    const emailGroups = {};
    users.forEach(user => {
      const email = user.email.toLowerCase();
      if (!emailGroups[email]) emailGroups[email] = [];
      emailGroups[email].push(user);
    });
    
    // Find duplicates
    const duplicates = Object.entries(emailGroups).filter(([email, users]) => users.length > 1);
    
    if (duplicates.length === 0) {
      console.log('✅ No duplicates found');
      process.exit(0);
    }
    
    console.log('🔍 Found duplicates:');
    for (const [email, userList] of duplicates) {
      console.log(`\n📧 ${email} (${userList.length} copies):`);
      userList.forEach((user, i) => {
        console.log(`  ${i+1}. ID: ${user._id} | Role: ${user.role} | Created: ${user.createdAt} | Permissions: ${Object.keys(user.permissions || {}).length}`);
      });
      
      // Keep the one with most permissions or latest created
      const keeper = userList.reduce((best, current) => {
        const bestPerms = Object.keys(best.permissions || {}).length;
        const currentPerms = Object.keys(current.permissions || {}).length;
        
        if (currentPerms > bestPerms) return current;
        if (currentPerms === bestPerms && current.createdAt > best.createdAt) return current;
        return best;
      });
      
      const toDelete = userList.filter(u => u._id.toString() !== keeper._id.toString());
      
      console.log(`  ✅ Keeping: ${keeper._id} (${Object.keys(keeper.permissions || {}).length} permissions)`);
      console.log(`  🗑️ Deleting: ${toDelete.map(u => u._id).join(', ')}`);
      
      // Delete duplicates
      for (const user of toDelete) {
        await User.findByIdAndDelete(user._id);
        console.log(`    Deleted: ${user._id}`);
      }
    }
    
    console.log('\n✅ Duplicates cleaned up!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

fixDuplicates();