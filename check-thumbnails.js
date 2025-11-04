require('dotenv').config();
const mongoose = require('mongoose');
const Model = require('./models/Model');

async function checkThumbnails() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    const models = await Model.find({}).select('name thumbnail').lean();
    console.log('\nModels with thumbnails:');
    models.forEach(m => {
      console.log(`${m.name}: ${m.thumbnail || 'null'}`);
    });

    console.log(`\nTotal models: ${models.length}`);
    const withThumbnails = models.filter(m => m.thumbnail).length;
    console.log(`Models with thumbnails: ${withThumbnails}`);

    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

checkThumbnails();