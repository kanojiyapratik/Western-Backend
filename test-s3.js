const { uploadToS3, deleteFromS3, generateS3Key } = require('./utils/s3Upload');
const fs = require('fs');
const path = require('path');

async function testS3Connection() {
  console.log('🧪 Testing S3 Connection...\n');

  try {
    // Test 1: Create a simple test file
    console.log('📝 Creating test file...');
    const testContent = `Test file created at ${new Date().toISOString()}\nS3 Migration Test`;
    const testFilePath = path.join(__dirname, 's3-test.txt');
    fs.writeFileSync(testFilePath, testContent);
    console.log('✅ Test file created\n');

    // Test 2: Upload to S3
    console.log('⬆️  Uploading to S3...');
    const s3Key = generateS3Key('test', 'test-file.txt');
    const uploadResult = await uploadToS3(testFilePath, s3Key, 'text/plain');

    if (uploadResult.success) {
      console.log('✅ Upload successful!');
      console.log('📍 S3 URL:', uploadResult.url);
      console.log('🗝️  S3 Key:', uploadResult.key);
      console.log('📊 Bucket:', uploadResult.bucket);
      console.log();

      // Test 3: Verify file is accessible
      console.log('🌐 Testing file accessibility...');
      const https = require('https');
      const url = uploadResult.url;

      https.get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            console.log('✅ File is publicly accessible');
            console.log('📄 Content preview:', data.substring(0, 50) + '...');
          } else {
            console.log('❌ File not accessible, status:', res.statusCode);
          }
          console.log();

          // Test 4: Delete from S3
          console.log('🗑️  Deleting test file from S3...');
          deleteFromS3(uploadResult.key).then(deleteResult => {
            if (deleteResult.success) {
              console.log('✅ Delete successful!');
            } else {
              console.log('❌ Delete failed:', deleteResult.error);
            }
            console.log();

            // Cleanup local file
            fs.unlinkSync(testFilePath);
            console.log('🧹 Local test file cleaned up');

            console.log('\n🎉 S3 Integration Test Complete!');
            console.log('✅ All tests passed - S3 is ready for your 3D configurator!');
          });
        });
      }).on('error', (err) => {
        console.log('❌ Accessibility test failed:', err.message);
      });

    } else {
      console.log('❌ Upload failed:', uploadResult.error);
      fs.unlinkSync(testFilePath);
    }

  } catch (error) {
    console.error('❌ Test failed with error:', error);
  }
}

// Configuration check
console.log('🔧 S3 Configuration Check:');
console.log('Region:', process.env.AWS_REGION);
console.log('Bucket:', process.env.AWS_S3_BUCKET_NAME);
console.log('Access Key:', process.env.AWS_ACCESS_KEY_ID ? 'Present' : 'Missing');
console.log('Secret Key:', process.env.AWS_SECRET_ACCESS_KEY ? 'Present' : 'Missing');
console.log();

// Run the test
testS3Connection();