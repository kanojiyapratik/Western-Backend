const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

/**
 * Generate thumbnail for 3D model using headless browser
 * @param {string} modelPath - Path to the 3D model file
 * @param {string} modelName - Name of the model for thumbnail filename
 * @returns {Promise<string>} - Thumbnail filename
 */
async function generateThumbnail(modelPath, modelName) {
  let browser;
  try {
    console.log(`🖼️ Generating thumbnail for: ${modelName}`);
    
    // Create thumbnails directory if it doesn't exist
    const thumbnailsDir = path.join(__dirname, '../../Frontend/public/thumbnails');
    if (!fs.existsSync(thumbnailsDir)) {
      fs.mkdirSync(thumbnailsDir, { recursive: true });
    }

    // Launch headless browser
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 512, height: 512 });

    // Create a simple HTML page with Three.js to render the model
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { margin: 0; padding: 0; background: #f0f0f0; }
        canvas { display: block; }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/GLTFLoader.js"></script>
</head>
<body>
    <script>
        // Three.js scene setup
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0xf0f0f0);
        
        const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(512, 512);
        renderer.shadowMap.enabled = true;
        renderer.shadowMap.type = THREE.PCFSoftShadowMap;
        document.body.appendChild(renderer.domElement);

        // Lighting
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
        scene.add(ambientLight);
        
        const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
        directionalLight.position.set(5, 5, 5);
        directionalLight.castShadow = true;
        scene.add(directionalLight);

        // Load model
        const loader = new THREE.GLTFLoader();
        loader.load('${modelPath}', function(gltf) {
            const model = gltf.scene;
            scene.add(model);

            // Auto-fit camera to model
            const box = new THREE.Box3().setFromObject(model);
            const center = box.getCenter(new THREE.Vector3());
            const size = box.getSize(new THREE.Vector3());
            
            const maxDim = Math.max(size.x, size.y, size.z);
            const fov = camera.fov * (Math.PI / 180);
            let cameraZ = Math.abs(maxDim / 2 / Math.tan(fov / 2));
            cameraZ *= 1.5; // Add some padding
            
            camera.position.set(center.x + cameraZ * 0.5, center.y + cameraZ * 0.3, center.z + cameraZ);
            camera.lookAt(center);
            
            // Render
            renderer.render(scene, camera);
            
            // Signal that rendering is complete
            window.renderComplete = true;
        }, undefined, function(error) {
            console.error('Error loading model:', error);
            window.renderError = true;
        });
    </script>
</body>
</html>`;

    await page.setContent(htmlContent);
    
    // Wait for model to load and render
    await page.waitForFunction(() => window.renderComplete || window.renderError, { timeout: 30000 });
    
    // Check if there was an error
    const hasError = await page.evaluate(() => window.renderError);
    if (hasError) {
      throw new Error('Failed to load 3D model in browser');
    }

    // Take screenshot
    const thumbnailFilename = `${modelName.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.png`;
    const thumbnailPath = path.join(thumbnailsDir, thumbnailFilename);
    
    await page.screenshot({
      path: thumbnailPath,
      clip: { x: 0, y: 0, width: 512, height: 512 }
    });

    console.log(`✅ Thumbnail generated: ${thumbnailFilename}`);
    return thumbnailFilename;

  } catch (error) {
    console.error('❌ Thumbnail generation failed:', error);
    return null;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

module.exports = { generateThumbnail };