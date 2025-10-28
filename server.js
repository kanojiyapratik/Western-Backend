// Backend/server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cloudinary = require('cloudinary').v2;

// Load environment variables first
require("dotenv").config();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

console.log('Cloudinary configured with:', {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'missing',
  api_key: process.env.CLOUDINARY_API_KEY ? 'present' : 'missing',
  api_secret: process.env.CLOUDINARY_API_SECRET ? 'present' : 'missing'
});
const ActivityLog = require("./models/ActivityLog");
const { sendEmbedEmail } = require("./utils/mailer");

const app = express();

// Helper to safely extract client IP (supports proxies if X-Forwarded-For present)
function getClientIp(req) {
  try {
    const xf = req.headers['x-forwarded-for'];
    if (xf) {
      // X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2
      const parts = xf.split(',').map(p => p.trim()).filter(Boolean);
      if (parts.length) return parts[0];
    }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '0.0.0.0';
  } catch (e) {
    return '0.0.0.0';
  }
}

// CORS Configuration - Environment-based
const allowedOrigins = [
  // Production origins
  'https://frontendwestern.netlify.app',
  'https://western-frontend.vercel.app',
  // Development origins - comprehensive localhost variations
  "http://localhost:3000",
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:5000",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
  "http://127.0.0.1:5000",
  // Network IPs for development
  "http://192.168.1.5:5173",
  "http://192.168.1.5:5174",
  "http://192.168.1.5:5000",
  "http://192.168.1.7:5173",
  "http://192.168.1.7:5174",
  "http://192.168.1.7:3000",
  "http://192.168.1.7:5000",
  "http://192.168.1.8:5173",
  "http://192.168.1.8:5174",
  "http://192.168.1.8:3000",
  "http://192.168.1.8:5000"
];

if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

console.log('🌐 CORS Origins:', allowedOrigins);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn('🚫 CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
}));

app.use(express.json({ limit: '50mb' })); // Increase JSON payload limit for configurations
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Also increase URL-encoded limit

// Ensure upload directories exist on startup
const ensureDirectoriesExist = () => {
  const dirs = [
    path.join(__dirname, '../Frontend/public/models'),
    path.join(__dirname, '../Frontend/public/textures'),
    path.join(__dirname, '../Frontend/public/texture'),
    path.join(__dirname, '../Frontend/public/thumbnails'),
    path.join(__dirname, '../Frontend/public/configs'),
    path.join(__dirname, '../Frontend/public/config-textures')
  ];

  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`✅ Created directory: ${dir}`);
    }
  });
};

// Call on startup
ensureDirectoriesExist();

// Serve uploaded models statically from backend
app.use('/models', express.static(path.join(__dirname, '../Frontend/public/models')));
// Serve textures statically from backend
app.use('/textures', express.static(path.join(__dirname, '../Frontend/public/textures')));
app.use('/texture', express.static(path.join(__dirname, '../Frontend/public/texture')));
// Serve thumbnails statically from backend
app.use('/thumbnails', express.static(path.join(__dirname, '../Frontend/public/thumbnails')));
// Serve developer-provided JSON configs
app.use('/configs', express.static(path.join(__dirname, '../Frontend/public/configs')));

// API route for updating config files
app.use('/api/configs', require('./routes/config'));

// Admin dashboard routes with permission-based access
app.use('/api/admin-dashboard', require('./routes/adminDashboard'));

// Connect to MongoDB
const MONGODB_URI = process.env.MONGO_URI || "mongodb://localhost:27017/3dconfigurator";

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// Import the correct User model from models/User.js (which supports all permissions)
const User = require('./models/User');


// Use new Model.js schema (with section)
const Model = require('./models/Model');

// SavedConfiguration Schema for user configurations
const SavedConfigurationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  modelName: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  configData: {
    // Model state data
    doorConfiguration: mongoose.Schema.Types.Mixed,  // Which doors are open/closed
    textureSettings: mongoose.Schema.Types.Mixed,    // Applied textures (with file paths)
    cameraPosition: mongoose.Schema.Types.Mixed,     // Camera state
    widgetStates: mongoose.Schema.Types.Mixed,       // Widget configurations
    visibilityStates: mongoose.Schema.Types.Mixed,   // What's visible/hidden
    customizations: mongoose.Schema.Types.Mixed      // Any other custom settings
  },
  textureFiles: [{                                   // Array of texture files for this config
    originalName: String,                            // Original filename from user
    savedPath: String,                               // Path where file is stored
    configKey: String,                               // Key in textureSettings this file corresponds to
    fileSize: Number,                                // File size in bytes
    mimeType: String,                                // MIME type of the file
    uploadedAt: { type: Date, default: Date.now }   // When texture was uploaded
  }],
  isPublic: { type: Boolean, default: false },      // For sharing configs
  tags: [String],                                    // For categorizing configs
  previewImage: String                               // Optional screenshot
}, { timestamps: true });

const SavedConfiguration = mongoose.model("SavedConfiguration", SavedConfigurationSchema);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, '../Frontend/public/models');
    // Directory creation is now handled by ensureDirectoriesExist() on startup
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB limit for very large models
  fileFilter: function (req, file, cb) {
    // Accept GLB/GLTF files and image files
    const allowedTypes = ['.glb', '.gltf', '.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only GLB, GLTF, and image files (JPG, PNG, BMP, TIFF, WebP) are allowed'), false);
    }
  }
});

// Configure multer for texture uploads
const textureStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, '../Frontend/public/texture');
    // Directory creation is now handled by ensureDirectoriesExist() on startup
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'texture-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadTexture = multer({ 
  storage: textureStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit for textures
  fileFilter: function (req, file, cb) {
    // Accept only image files
    const allowedTypes = ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPG, PNG, BMP, TIFF, WebP) are allowed'), false);
    }
  }
});

// Helper functions for asset parsing and deletion
function analyzeAssetString(assetStr) {
  if (!assetStr || typeof assetStr !== 'string') return null;
  
  let relPath = assetStr;
  let type = 'models'; // default
  
  // Handle full URLs
  if (assetStr.startsWith('http://') || assetStr.startsWith('https://')) {
    if (assetStr.includes('/models/')) {
      relPath = assetStr.split('/models/')[1];
      type = 'models';
    } else if (assetStr.includes('/configs/')) {
      relPath = assetStr.split('/configs/')[1];
      type = 'configs';
    } else if (assetStr.includes('/texture/') || assetStr.includes('/textures/')) {
      relPath = assetStr.split('/texture')[1] || assetStr.split('/textures/')[1];
      type = 'texture';
    }
  } 
  // Handle relative paths
  else if (assetStr.startsWith('/models/')) {
    relPath = assetStr.substring(8);
    type = 'models';
  } else if (assetStr.startsWith('/configs/')) {
    relPath = assetStr.substring(9);
    type = 'configs';
  } else if (assetStr.startsWith('/texture/') || assetStr.startsWith('/textures/')) {
    relPath = assetStr.substring(9);
    type = 'texture';
  } else if (assetStr.startsWith('texture/') || assetStr.startsWith('textures/')) {
    relPath = assetStr.substring(8);
    type = 'texture';
  }
  // Bare filename - assume models
  else {
    relPath = assetStr;
    type = 'models';
  }
  
  return { relPath, type };
}

function collectAssetStrings(value) {
  const assets = { models: new Set(), configs: new Set(), texture: new Set() };
  
  function recurse(obj) {
    if (typeof obj === 'string') {
      const analyzed = analyzeAssetString(obj);
      if (analyzed) {
        assets[analyzed.type].add(analyzed.relPath);
      }
    } else if (Array.isArray(obj)) {
      obj.forEach(recurse);
    } else if (obj && typeof obj === 'object') {
      Object.values(obj).forEach(recurse);
    }
  }
  
  recurse(value);
  return assets;
}

async function performModelDeletion(model) {
  const report = { deleted: [], notFound: [], errors: [] };
  
  try {
    const { deleteFromCloudinary } = require('./utils/cloudinaryUpload');
    
    // Delete main file from Cloudinary if it's a Cloudinary URL
    if (model.path && model.path.includes('cloudinary.com')) {
      try {
        // Extract public_id from Cloudinary URL
        // URL format: https://res.cloudinary.com/cloud/image/upload/v123/folder/filename.ext
        const urlParts = model.path.split('/');
        // Find the part after 'upload/v{version}/' which contains folder/filename
        const uploadIndex = urlParts.findIndex(part => part.startsWith('v') && /^v\d+$/.test(part));
        let fullPublicId;
        if (uploadIndex !== -1 && uploadIndex + 1 < urlParts.length) {
          // Get everything after version (folder/filename.ext)
          const pathAfterVersion = urlParts.slice(uploadIndex + 1).join('/');
          fullPublicId = pathAfterVersion.replace(/\.[^.]+$/, ''); // remove extension
        } else {
          // Fallback to old method
          const fileWithExt = urlParts[urlParts.length - 1];
          fullPublicId = `models/${fileWithExt.split('.')[0]}`;
        }
        console.log(`Model data:`, { file: model.file, path: model.path });
        console.log(`Extracted public_id: ${fullPublicId}`);
        
        // Check all files in Cloudinary (both raw and image types)
        try {
          const cloudinary = require('cloudinary').v2;
          
          // Check RAW files
          const rawResult = await cloudinary.api.resources({
            type: 'upload',
            resource_type: 'raw',
            max_results: 20
          });
          console.log('All RAW files in Cloudinary:', rawResult.resources.map(r => ({ public_id: r.public_id, url: r.secure_url })));
          
          // Check IMAGE files
          const imageResult = await cloudinary.api.resources({
            type: 'upload',
            resource_type: 'image',
            max_results: 20
          });
          console.log('All IMAGE files in Cloudinary:', imageResult.resources.map(r => ({ public_id: r.public_id, url: r.secure_url })));
          
          // Try to find our specific file
          const allFiles = [...rawResult.resources, ...imageResult.resources];
          const matchingFile = allFiles.find(f => f.public_id === fullPublicId);
          console.log('Matching file found:', matchingFile ? { public_id: matchingFile.public_id, resource_type: matchingFile.resource_type, url: matchingFile.secure_url } : 'NOT FOUND');
          
        } catch (err) {
          console.log('Could not list Cloudinary files:', err.message);
        }
        
        console.log(`Deleting from Cloudinary: ${fullPublicId}`);
        console.log(`URL analysis: ${model.path}`);
        console.log(`URL parts:`, model.path.split('/'));
        const deleteResult = await deleteFromCloudinary(fullPublicId, 'image');
        if (deleteResult.success) {
          report.deleted.push(`cloudinary/${fullPublicId}`);
        } else {
          report.errors.push(`Failed to delete from Cloudinary: ${deleteResult.error}`);
        }
      } catch (err) {
        report.errors.push(`Cloudinary deletion error: ${err.message}`);
      }
    }
    
    // Delete assets from Cloudinary
    if (model.assets && typeof model.assets === 'object') {
      for (const [key, assetUrl] of Object.entries(model.assets)) {
        if (assetUrl && assetUrl.includes('cloudinary.com')) {
          try {
            // Extract public_id from Cloudinary URL
            const urlParts = assetUrl.split('/');
            const fileWithExt = urlParts[urlParts.length - 1];
            const publicId = fileWithExt.split('.')[0];
            const fullPublicId = `models/${publicId}`;
            
            console.log(`Deleting asset from Cloudinary: ${fullPublicId}`);
            const deleteResult = await deleteFromCloudinary(fullPublicId, 'image');
            if (deleteResult.success) {
              report.deleted.push(`cloudinary/${fullPublicId}`);
            } else {
              report.errors.push(`Failed to delete asset from Cloudinary: ${deleteResult.error}`);
            }
          } catch (err) {
            report.errors.push(`Asset deletion error: ${err.message}`);
          }
        }
      }
    }
    
    // Delete local config file if exists
    if (model.configUrl && typeof model.configUrl === 'string' && model.configUrl.startsWith('/configs/')) {
      const configRel = model.configUrl.substring(9);
      const configPath = path.join(__dirname, '../Frontend/public/configs', configRel);
      if (fs.existsSync(configPath)) {
        try {
          fs.unlinkSync(configPath);
          report.deleted.push(`configs/${configRel}`);
        } catch (err) {
          report.errors.push(`Failed to delete config: ${err.message}`);
        }
      }
    }
    
    // Delete from DB
    await Model.findByIdAndDelete(model._id);
    report.deleted.push('database record');
    
  } catch (error) {
    report.errors.push(`Deletion error: ${error.message}`);
  }
  
  return report;
}

// Utility function to copy texture files for configuration storage
async function copyTextureForConfig(sourcePath, configId, textureKey) {
  try {
    console.log(`📂 copyTextureForConfig called with:`, { sourcePath, configId, textureKey });

    const configTexturesPath = path.join(__dirname, '../Frontend/public/config-textures', configId);
    console.log(`📂 Config textures path: ${configTexturesPath}`);

    // Directory creation is now handled by ensureDirectoriesExist() on startup
    // But we still need to create the specific configId subdirectory
    if (!fs.existsSync(configTexturesPath)) {
      fs.mkdirSync(configTexturesPath, { recursive: true });
      console.log(`📂 Created config-specific directory: ${configTexturesPath}`);
    }
    
    const sourceFullPath = path.join(__dirname, '../Frontend/public', sourcePath);
    const filename = `${textureKey}-${path.basename(sourcePath)}`;
    const destinationPath = path.join(configTexturesPath, filename);
    
    console.log(`📂 Source path: ${sourceFullPath}`);
    console.log(`📂 Destination path: ${destinationPath}`);
    
    // Check if source file exists
    if (!fs.existsSync(sourceFullPath)) {
      throw new Error(`Source texture file not found: ${sourceFullPath}`);
    }
    
    // Copy the file
    await fs.promises.copyFile(sourceFullPath, destinationPath);
    console.log(`✅ File copied successfully`);
    
    // Return the relative path for frontend access
    const relativePath = `/config-textures/${configId}/${filename}`;
    console.log(`📂 Returning relative path: ${relativePath}`);
    return relativePath;
  } catch (error) {
    console.error('❌ Error copying texture file:', error);
    throw error;
  }
}

// Utility function to clean up texture files when configuration is deleted
async function cleanupConfigTextures(configId) {
  try {
    const configTexturesPath = path.join(__dirname, '../Frontend/public/config-textures', configId);
    if (!fs.existsSync(configTexturesPath)) {
      return;
    }

    // Prefer newer fs.rm if available, with force to avoid permission issues
    if (fs.promises.rm) {
      try {
        await fs.promises.rm(configTexturesPath, { recursive: true, force: true });
        return;
      } catch (rmErr) {
        console.warn('cleanupConfigTextures: fs.promises.rm failed, falling back to rmdir:', rmErr && (rmErr.stack || rmErr));
      }
    }

    // Fallback for older Node versions
    try {
      await fs.promises.rmdir(configTexturesPath, { recursive: true });
    } catch (rmdirErr) {
      console.error('cleanupConfigTextures: rmdir failed:', rmdirErr && (rmdirErr.stack || rmdirErr));
    }
  } catch (error) {
    console.error('Error cleaning up texture files (unexpected):', error && (error.stack || error));
  }
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-here";

// Simple in-memory SSE clients map: userId -> Set of response objects
const sseClients = new Map();

// Helper to send SSE event to a specific user
function sendSseEventToUser(userId, eventName, payload = {}) {
  const set = sseClients.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const res of set) {
    try {
      res.write(`event: ${eventName}\n`);
      res.write(`data: ${data}\n\n`);
    } catch (err) {
      console.warn('SSE write failed for user', userId, err && err.message);
    }
  }
}

// Ensure default demo accounts exist and match expected credentials/permissions
const ensureDefaultAccounts = async () => {
  try {
    const ensureAccount = async ({
      email,
      name,
      role,
      password,
      permissions
    }) => {
      let user = await User.findOne({ email });
      if (!user) {
        await User.create({
          name,
          email,
          password, // let model middleware handle hashing
          role,
          permissions
        });
        console.log(`✅ Default ${role} account created: ${email} / ${password}`);
        return;
      }

      // If user exists, make sure password, role, permissions and active status are as expected
      const passwordMatches = await bcrypt.compare(password, user.password);
      const updates = {};
      if (!passwordMatches) updates.password = password; // let model middleware handle hashing
      if (user.role !== role) updates.role = role;
      // Restore full demo permissions to avoid "No Configuration" state
      updates.permissions = permissions;
  // Legacy 'isActive' removed - no active flag to update

      if (Object.keys(updates).length) {
        await User.updateOne({ _id: user._id }, { $set: updates });
        console.log(`🔄 Default ${role} account reset: ${email}`);
      } else {
        console.log(`✅ Default ${role} account verified: ${email}`);
      }
    };

    const fullPermissions = {
      doorPresets: true,
      doorToggles: true,
      drawerToggles: true,
      textureWidget: true,
      lightWidget: true,
      globalTextureWidget: true,
      screenshotWidget: true,
      modelUpload: true,
      // Add missing widget permissions
  // Removed reflectionWidget, movementWidget, customWidget
      saveConfig: true,
      canRotate: true,
      canPan: true,
      canZoom: true,
      canMove: true
    };

    await ensureAccount({
      email: "admin@example.com",
      name: "Admin User",
      role: "admin",
      password: "admin123",
      permissions: fullPermissions
    });

    await ensureAccount({
      email: "user@example.com",
      name: "Demo User",
      role: "employee",
      password: "user123",
      permissions: fullPermissions
    });

    await ensureAccount({
      email: "super@gmail.com",
      name: "Super Admin",
      role: "superadmin",
      password: "-1234",
      permissions: fullPermissions
    });
  } catch (error) {
    console.error("❌ Error ensuring default accounts:", error.message);
  }
};

// Auth middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    
    if (!user) {
      return res.status(401).json({ message: "Invalid token" });
    }

    // Legacy account active/deactivated flag removed; proceed with request

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Routes
app.post("/api/auth/register", async (req, res) => {
  try {
  // Prevent public self-registration unless explicitly enabled
  if (process.env.ALLOW_SELF_REGISTRATION !== 'true') {
    return res.status(403).json({ message: "Self-registration is disabled. Please contact your administrator." });
  }

  let { name, email, password } = req.body;
  // Normalize inputs
  email = (email || "").toLowerCase().trim();
  password = (password || "").trim();
  name = (name || "").trim();
    
    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    
    // Create user (let model middleware handle hashing)
    const user = await User.create({
      name,
      email,
      password,
      permissions: {
        canRotate: true,
        doorPresets: false,
        doorToggles: false,
        drawerToggles: false,
        textureWidget: false,
        lightWidget: false,
        globalTextureWidget: false,
        canPan: false,
        canZoom: false
      }
    });
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
  let { email, password } = req.body;
  email = (email || "").toLowerCase().trim();
  password = (password || "").trim();
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Find user
  const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    // Legacy account activation flag removed; proceed with password check

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: "Invalid password" });
    }
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// Token verification endpoint
app.get("/api/auth/verify", authMiddleware, async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        permissions: req.user.permissions
      }
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(401).json({ message: "Invalid token" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      permissions: req.user.permissions
    }
  });
});

// Password reset endpoints (OTP)
app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetOtp = otp;
    user.resetOtpExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const subject = 'Your password reset code';
    const html = `<p>Your password reset code is <strong>${otp}</strong>. It expires in 15 minutes.</p>`;
    const emailResult = await sendEmbedEmail(user.email, subject, html);
    if (!emailResult.success) return res.status(500).json({ message: 'Failed to send reset email', error: emailResult.error });

    res.json({ message: 'OTP sent to email' });
  } catch (error) {
    console.error('request-password-reset error:', error);
    res.status(500).json({ message: 'Error requesting password reset', error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) return res.status(400).json({ message: 'Email, otp and newPassword are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.resetOtp || !user.resetOtpExpires) return res.status(400).json({ message: 'No reset requested' });
    if (user.resetOtp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
    if (user.resetOtpExpires < new Date()) return res.status(400).json({ message: 'OTP expired' });

    // set new password (let the model middleware handle hashing)
    user.password = newPassword;
    user.resetOtp = undefined;
    user.resetOtpExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('reset-password error:', error);
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ message: 'currentPassword and newPassword are required' });

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) return res.status(400).json({ message: 'Current password is incorrect' });

    // set new password (let the model middleware handle hashing)
    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('change-password error:', error);
    res.status(500).json({ message: 'Error changing password', error: error.message });
  }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Server is running", timestamp: new Date().toISOString() });
});

// Note: Admin dashboard routes are now handled by /routes/adminDashboard.js with proper permission-based access control

// Call after MongoDB connection
mongoose.connection.on("connected", () => {
  ensureDefaultAccounts();
});
// Get activity logs (accessible to both admin and users)
app.get("/api/activity/logs", authMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, startDate, endDate, action } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = {};
    
    if (req.user.role === "user") {
      // Users can only see their own logs and public logs
      filter.$or = [
        { userId: req.user._id },
        { visibility: "public" }
      ];
    } else if (req.user.role === "admin") {
      // Admins can see all logs
      if (req.query.userId) {
        filter.userId = req.query.userId;
      }
    }
    
    // Date filtering
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = new Date(startDate);
      if (endDate) filter.timestamp.$lte = new Date(endDate);
    }
    
    // Action filtering
    if (action) {
      filter.action = new RegExp(action, 'i');
    }

    const logs = await ActivityLog.find(filter)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'name email role');

    const total = await ActivityLog.countDocuments(filter);

    res.json({
      logs,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total,
      userRole: req.user.role
    });
  } catch (error) {
    console.error("Get activity logs error:", error);
    res.status(500).json({ message: "Error fetching activity logs", error: error.message });
  }
});

// Log model interaction (with simple SHA256 chaining for tamper-evidence)
const crypto = require('crypto');

app.post("/api/activity/log", authMiddleware, async (req, res) => {
  try {
    const { action, modelName, partName, widgetType, details, visibility = "user" } = req.body;
    const ip = getClientIp(req);
    const userAgent = req.get('User-Agent') || '';

    // Get last log hash to chain
    const lastLog = await ActivityLog.findOne({}).sort({ createdAt: -1 }).select('hash').lean();
    const previousHash = lastLog?.hash || null;

    // Build the record payload used for hashing (stable deterministic ordering)
    const payload = {
      userId: req.user._id?.toString(),
      userEmail: req.user.email,
      action: action,
      modelName: modelName || "",
      partName: partName || "",
      widgetType: widgetType || "",
      details: details || {},
      ipAddress: ip,
      userAgent: userAgent,
      timestamp: new Date().toISOString(),
      previousHash: previousHash
    };

    const payloadString = JSON.stringify(payload);
    const hash = crypto.createHash('sha256').update(payloadString).digest('hex');

    const log = await ActivityLog.create({
      userId: req.user._id,
      userEmail: req.user.email,
      userName: req.user.name,
      action: action,
      details: details || {},
      ipAddress: ip,
      userAgent: userAgent,
      modelName: modelName || "",
      partName: partName || "",
      widgetType: widgetType || "",
      visibility: visibility,
      timestamp: new Date(),
      previousHash,
      hash
    });

    res.json({ message: "Activity logged successfully", log });
  } catch (error) {
    console.error("Activity logging error:", error);
    res.status(500).json({ message: "Error logging activity", error: error.message });
  }
});

// Reusable helper to append an ActivityLog entry (keeps chain integrity)
async function appendActivityLogEntry({ user, action, details = {}, modelName = "", partName = "", widgetType = "", visibility = 'admin' }) {
  try {
    const ip = '0.0.0.0';
    const userAgent = 'system';
    // Get last log hash to chain
    const lastLog = await ActivityLog.findOne({}).sort({ createdAt: -1 }).select('hash').lean();
    const previousHash = lastLog?.hash || null;

    const payload = {
      userId: user?._id?.toString() || null,
      userEmail: user?.email || (user?._id ? String(user._id) : 'system'),
      action,
      modelName,
      partName,
      widgetType,
      details,
      ipAddress: ip,
      userAgent,
      timestamp: new Date().toISOString(),
      previousHash
    };

    const payloadString = JSON.stringify(payload);
    const hash = crypto.createHash('sha256').update(payloadString).digest('hex');

    const log = await ActivityLog.create({
      userId: user?._id || null,
      userEmail: user?.email || (user?._id ? String(user._id) : 'system'),
      userName: user?.name || (user?.email ? user.email.split('@')[0] : 'system'),
      action,
      details,
      ipAddress: ip,
      userAgent,
      modelName,
      partName,
      widgetType,
      visibility,
      timestamp: new Date(),
      previousHash,
      hash
    });

    return log;
  } catch (err) {
    console.error('appendActivityLogEntry error:', err);
    throw err;
  }
}

// Export verification proof for a range (simple proof: returns ordered logs with hashes)
app.get('/api/activity/proof', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    const { from = 0, limit = 100 } = req.query;
    const logs = await ActivityLog.find({}).sort({ createdAt: 1 }).skip(parseInt(from)).limit(parseInt(limit)).lean();
    // Return logs with hash and previousHash for external verification
    res.json({ count: logs.length, logs });
  } catch (err) {
    console.error('Activity proof export error:', err);
    res.status(500).json({ message: 'Error exporting activity proof', error: err.message });
  }
});

// Get statistics for dashboard
app.get("/api/activity/stats", authMiddleware, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    let filter = { timestamp: { $gte: thirtyDaysAgo } };
    
    if (req.user.role === "user") {
      filter.userId = req.user._id;
    }

    const stats = await ActivityLog.aggregate([
      { $match: filter },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } },
      { $limit: 30 }
    ]);

    const totalActions = await ActivityLog.countDocuments(filter);
    const popularActions = await ActivityLog.aggregate([
      { $match: filter },
      { $group: { _id: "$action", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    res.json({
      dailyStats: stats,
      totalActions,
      popularActions,
      timeFrame: "30 days"
    });
  } catch (error) {
    console.error("Get activity stats error:", error);
    res.status(500).json({ message: "Error fetching activity stats", error: error.message });
  }
});


// Import modelManagement routes
const modelManagementRoutes = require('./routes/modelManagement');
// Model Management Routes

// Get active models for users (no auth required for viewing models)
app.use(modelManagementRoutes);
app.get("/api/models", async (req, res) => {
  try {
    console.log('=== MODELS API REQUEST ===');
    const allModels = await Model.find({}).select('name status createdAt');
    console.log('All models in DB:', allModels.map(m => ({ name: m.name, status: m.status, created: m.createdAt })));
    
    const models = await Model.find({ status: 'active' }).select('-uploadedBy -createdAt -updatedAt');
    console.log('Active models found:', models.length);
    
    // Convert to format expected by frontend
    const formattedModels = models.map(model => {
      const meta = model.metadata || {};
      // Normalize uiWidgets: prefer top-level uiWidgets, fallback to metadata.uiWidgets
      const uiWidgets = Array.isArray(model.uiWidgets) && model.uiWidgets.length
        ? model.uiWidgets
        : (Array.isArray(meta.uiWidgets) ? meta.uiWidgets : []);

      // Normalize lights and hiddenInitially from either top-level or metadata (backward compatibility)
      const lights = Array.isArray(model.lights) && model.lights.length
        ? model.lights
        : (Array.isArray(meta.lights) ? meta.lights : []);
      const hiddenInitially = Array.isArray(model.hiddenInitially) && model.hiddenInitially.length
        ? model.hiddenInitially
        : (Array.isArray(meta.hiddenInitially) ? meta.hiddenInitially : []);

      // Normalize asset paths to absolute backend URLs so the frontend (on port 5173) can load them
      const normalizeAssetPath = (p) => {
        if (!p || typeof p !== 'string') return undefined;
        if (p.startsWith('http://') || p.startsWith('https://')) return p;
        const baseUrl = process.env.NODE_ENV === 'production'
          ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
          : (process.env.LOCAL_BACKEND_URL || 'http://localhost:5000');
        if (p.startsWith('/models/')) return `${baseUrl}${p}`;
        // treat as filename - only add /models/ prefix if it's not already a full URL
        return `${baseUrl}/models/${p}`;
      };

      // For localhost development, ensure Cloudinary URLs are used directly without modification
      const normalizeAssetPathDev = (p) => {
        if (!p || typeof p !== 'string') return undefined;
        if (p.startsWith('http://') || p.startsWith('https://')) return p; // Cloudinary URLs stay as-is
        const baseUrl = process.env.NODE_ENV === 'production'
          ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
          : (process.env.LOCAL_BACKEND_URL || 'http://localhost:5000');
        if (p.startsWith('/models/')) return `${baseUrl}${p}`;
        return `${baseUrl}/models/${p}`;
      };
      const assetsRaw = model.assets || undefined;
      // Expose ALL asset keys, not just base/doors/drawers/glassDoors
      const assets = assetsRaw && typeof assetsRaw === 'object'
        ? Object.fromEntries(
            Object.entries(assetsRaw).map(([key, value]) => [key, normalizeAssetPath(value)])
          )
        : undefined;

      // Normalize config URL to absolute so the frontend can fetch it regardless of port
      const normalizeConfigUrl = (u) => {
        if (!u || typeof u !== 'string') return undefined;
        if (u.startsWith('http://') || u.startsWith('https://')) return u;
        const baseUrl = process.env.NODE_ENV === 'production' 
          ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
          : (process.env.LOCAL_BACKEND_URL || 'http://localhost:5000');
        if (u.startsWith('/')) return `${baseUrl}${u}`;
        return `${baseUrl}/${u}`;
      };

      return {
        id: model._id,
        name: model.name,
        displayName: model.displayName,
        file: model.path && model.path.includes('cloudinary.com') ? model.path :
          (process.env.NODE_ENV === 'production'
            ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
            : (process.env.LOCAL_BACKEND_URL || 'http://localhost:5000')) + (model.file && model.file.startsWith('/models/') ? model.file : `/models/${model.file || ''}`),
        section: model.section || 'Upright Counter',
        type: model.type,
        // Fallback to metadata.configUrl for legacy/older records
        configUrl: normalizeConfigUrl(model.configUrl || meta.configUrl) || undefined,
        interactionGroups: model.interactionGroups || [],
        metadata: { ...meta, uiWidgets },
        // Also expose commonly used fields at top-level for the viewer
        uiWidgets,
        lights,
        hiddenInitially,
        camera: model.camera || meta.camera || undefined,
        assets,
        presets: model.presets || undefined,
        // Expose admin-defined placement/transform so the viewer can apply it
        placementMode: model.placementMode || 'autofit',
        modelPosition: Array.isArray(model.modelPosition) ? model.modelPosition : undefined,
        modelRotation: Array.isArray(model.modelRotation) ? model.modelRotation : undefined,
        modelScale: typeof model.modelScale === 'number' ? model.modelScale : undefined
      };
    });
    
    console.log('=== MODELS API DEBUG ===');
    console.log('Raw models from DB:', models.length);
    if (models.length > 0) {
      console.log('Sample model metadata:', models[0].metadata);
      console.log('Sample exposed fields (top-level):', {
        uiWidgets: formattedModels[0]?.uiWidgets?.length || 0,
        lights: formattedModels[0]?.lights?.length || 0,
        hiddenInitially: formattedModels[0]?.hiddenInitially?.length || 0,
        hasCamera: !!formattedModels[0]?.camera,
        hasAssets: !!formattedModels[0]?.assets,
        hasPresets: !!formattedModels[0]?.presets,
      });
      console.log('Sample placement fields:', {
        placementMode: models[0].placementMode,
        modelPosition: models[0].modelPosition,
        modelRotation: models[0].modelRotation,
        modelScale: models[0].modelScale
      });
    }
    console.log('Formatted models (with placement & assets):', formattedModels);
    console.log('=======================');
    
    res.json(formattedModels);
  } catch (error) {
    console.error("Get models error:", error);
    res.status(500).json({ message: "Error fetching models", error: error.message });
  }
});

// Admin only routes (allow superadmin as well)
const requireAdmin = (req, res, next) => {
  if (!req.user || !(req.user.role === 'admin' || req.user.role === 'superadmin')) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Allow model management (list/view) if admin/superadmin OR any model-management permission
const requireModelManager = (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
  const p = req.user.permissions || {};
  if (p.modelUpload || p.modelManageUpload || p.modelManageEdit || p.modelManageDelete) return next();
  return res.status(403).json({ message: 'Model management permission required' });
};

// Action-specific permissions (legacy modelUpload implies all)
const requireModelUploadPerm = (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
  const p = req.user.permissions || {};
  // Only granular flag allows upload; master enables view-only
  if (p.modelManageUpload) return next();
  return res.status(403).json({ message: 'Upload permission required' });
};

const requireModelEditPerm = (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
  const p = req.user.permissions || {};
  if (p.modelManageEdit) return next();
  return res.status(403).json({ message: 'Edit permission required' });
};

const requireModelDeletePerm = (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
  if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
  const p = req.user.permissions || {};
  if (p.modelManageDelete) return next();
  return res.status(403).json({ message: 'Delete permission required' });
};

// Get all models
app.get("/api/admin/models", authMiddleware, requireModelManager, async (req, res) => {
  try {
    console.log('Admin /api/admin/models requested by user:', req.user?._id, req.user?.email, 'role=', req.user?.role);
    // Use lean() to return plain objects and avoid potential populate/schema mismatches
    let query = Model.find();
    // Only populate if the schema actually has uploadedBy path
    if (Model.schema.path('uploadedBy')) {
      query = query.populate('uploadedBy', 'name email');
    }
    const models = await query.lean();
    res.json(models);
  } catch (error) {
    console.error("Get models error:", error, error.stack);
    res.status(500).json({ message: "Error fetching models", error: error.message });
  }
});

// Upload new model
// Multi-file upload: expects fields like base, doors, drawers, etc.
app.post("/api/admin/models/upload", authMiddleware, requireModelUploadPerm, upload.fields([
  { name: 'base', maxCount: 1 },
  { name: 'doors', maxCount: 1 },
  { name: 'drawers', maxCount: 1 },
  { name: 'glassDoors', maxCount: 1 },
  { name: 'other', maxCount: 1 },
  { name: 'config', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('=== MODEL UPLOAD START ===');
    const { name, displayName, type, interactionGroups, metadata } = req.body;
    console.log('Received fields:', { name, displayName, type });
    console.log('Files received:', Object.keys(req.files || {}));

    // Parse JSON strings
    const parsedInteractionGroups = interactionGroups ? JSON.parse(interactionGroups) : [];
    const parsedMetadata = metadata ? JSON.parse(metadata) : {};
    console.log('Parsed Interaction Groups:', parsedInteractionGroups);
    console.log('Parsed Metadata:', parsedMetadata);

    // Upload files to Cloudinary
    const { uploadToCloudinary } = require('./utils/cloudinaryUpload');
    const assets = {};
    const assetUrls = {};
    
    try {
      for (const key of ['base', 'doors', 'drawers', 'glassDoors', 'other']) {
        if (req.files && req.files[key] && req.files[key][0]) {
          const file = req.files[key][0];
          console.log(`Uploading ${key} file: ${file.path} (${(file.size / (1024 * 1024)).toFixed(2)} MB)`);
          console.log('Cloudinary config:', {
            cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
            api_key: process.env.CLOUDINARY_API_KEY ? 'present' : 'missing',
            api_secret: process.env.CLOUDINARY_API_SECRET ? 'present' : 'missing'
          });

          try {
            const uploadResult = await uploadToCloudinary(file.path, {
              folder: 'models',
              public_id: `${name}_${key}`,
              use_filename: true,
              unique_filename: false
            });

            if (uploadResult.success) {
              assets[key] = uploadResult.public_id;
              assetUrls[key] = uploadResult.url;
              console.log(`✅ Asset uploaded to Cloudinary: ${key} -> ${uploadResult.url}`);
            } else {
              console.error(`❌ Failed to upload ${key}:`, uploadResult.error);
              // Continue with other uploads instead of failing completely
              console.warn(`⚠️ Skipping ${key} upload due to error, continuing with other assets`);
            }
          } catch (uploadError) {
            console.error(`❌ Exception during ${key} upload:`, uploadError.message);
            console.warn(`⚠️ Skipping ${key} upload due to exception, continuing with other assets`);
          }
        } else {
          console.log(`⏭️ No ${key} file provided, skipping`);
        }
      }
    } catch (error) {
      console.error('❌ Cloudinary upload error:', error);
      // Continue with model creation even if some assets failed to upload
      console.warn('⚠️ Some assets failed to upload, but continuing with model creation');
    }

    // Use base as main file if present
    const mainFile = assets.base;
    const mainFileUrl = assetUrls.base;
    if (!mainFile) {
      console.error('No base model file uploaded.');
      return res.status(400).json({ message: "No base model file uploaded" });
    }

    // Log which assets were successfully uploaded
    console.log('✅ Successfully uploaded assets:', Object.keys(assets));
    console.log('📋 Asset URLs:', assetUrls);
    console.log('📊 Upload summary:', {
      totalAssets: Object.keys(req.files || {}).length,
      successfulUploads: Object.keys(assets).length,
      failedUploads: Object.keys(req.files || {}).filter(key => req.files[key] && req.files[key][0] && !assets[key]).length
    });


    // Handle uploaded config file
    const fs = require('fs');
    const pathModule = require('path');
    let configUrl = null;
    if (req.files && req.files.config && req.files.config[0]) {
      const configFile = req.files.config[0];
      const configDir = pathModule.join(__dirname, '../Frontend/public/configs');
      // Directory creation is now handled by ensureDirectoriesExist() on startup
      const newConfigPath = pathModule.join(configDir, `${name}.json`);
      // Move the uploaded file to the new name
      fs.renameSync(configFile.path, newConfigPath);
      configUrl = `/configs/${name}.json`;
      console.log(`Config saved as: ${configUrl}`);
    }

    const newModel = new Model({
      name,
      displayName,
      path: mainFileUrl,
      file: mainFile, // Store the public_id without extension
      type,
      status: 'active', // Ensure model is active
      assets: assetUrls, // Store Cloudinary URLs
      interactionGroups: parsedInteractionGroups,
      metadata: parsedMetadata,
      uploadedBy: req.user._id,
      configUrl: configUrl,
      section: req.body.section || 'Upright Counter'
    });

    console.log('📋 Model data to be saved:', {
      name: newModel.name,
      path: newModel.path,
      file: newModel.file,
      assets: newModel.assets,
      configUrl: newModel.configUrl
    });

    await newModel.save();
    await newModel.populate('uploadedBy', 'name email');

    // Thumbnail generation removed

    // Generate JSON configuration template with asset URLs
    const jsonConfigTemplate = {
      name: name || displayName,
      path: mainFileUrl,
      assets: assetUrls,
      camera: {
        position: [0, 2, 5],
        target: [0, 1, 0],
        fov: 50
      },
      placementMode: "autofit",
      hiddenInitially: [],
      interactionGroups: parsedInteractionGroups.length > 0 ? parsedInteractionGroups : [
        // Example interaction groups - admin can modify these
        {
          type: "doors",
          label: "Doors",
          parts: []
        },
        {
          type: "drawers",
          label: "Drawers",
          parts: []
        }
      ],
      presets: {
        doorSelections: {}
      },
      doorTypeMap: {
        toGlass: {},
        toSolid: {}
      },
      uiWidgets: [],
      lights: [],
      metadata: {
        ...parsedMetadata,
        solidDoorMeshPrefixes: [],
        panels: [],
        glassPanels: [],
        drawers: {
          targetGroups: [],
          closedZ: 0,
          openZ: 0
        }
      }
    };

  // Write config file to public/configs and update model with configUrl
  // Reuse existing configUrl variable defined earlier for uploaded config file
  configUrl = configUrl || null;
    try {
      const { writeModelConfig } = require('./utils/configWriter');
      configUrl = writeModelConfig(name || displayName, jsonConfigTemplate);
      newModel.configUrl = configUrl;
      await newModel.save();
      console.log('Config file written at:', configUrl);
    } catch (configErr) {
      console.error('❌ Error writing config file:', configErr);
      return res.status(500).json({ message: 'Model uploaded but failed to write config file', error: configErr.message });
    }

    console.log('✅ Model saved successfully:', newModel._id);
    console.log('📋 Final model data:', {
      id: newModel._id,
      name: newModel.name,
      path: newModel.path,
      assets: newModel.assets,
      configUrl: newModel.configUrl
    });
    console.log('📄 Generated JSON config template:', JSON.stringify(jsonConfigTemplate, null, 2));

    res.status(201).json({
      message: "Model uploaded successfully",
      model: newModel,
      configUrl,
      assetUrls: assetUrls,
      uploadedAssets: Object.keys(assets),
      failedAssets: Object.keys(req.files || {}).filter(key => !assets[key] && req.files[key] && req.files[key][0])
    });
    console.log('=== MODEL UPLOAD END ===');
  } catch (error) {
    console.error("Upload model error:", error);
    // Clean up uploaded files on error
    if (req.files) {
      Object.values(req.files).forEach(arr => {
        arr.forEach(fileObj => {
          const filePath = path.join(__dirname, '../Frontend/public/models', fileObj.filename);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`Deleted file due to error: ${fileObj.filename}`);
          }
        });
      });
    }
    res.status(500).json({ message: "Error uploading model", error: error.message });
    console.log('=== MODEL UPLOAD ERROR END ===');
  }
});

// Simple file upload endpoint (uploads to Cloudinary)
app.post("/api/upload", authMiddleware, requireModelUploadPerm, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    console.log('Uploading file to Cloudinary:', req.file.path);
    console.log('Cloudinary config check:', {
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'missing',
      api_key: process.env.CLOUDINARY_API_KEY ? 'present' : 'missing',
      api_secret: process.env.CLOUDINARY_API_SECRET ? 'present' : 'missing'
    });

    // Upload to Cloudinary
    const { uploadToCloudinary } = require('./utils/cloudinaryUpload');
    const uploadResult = await uploadToCloudinary(req.file.path, {
      folder: 'models',
      public_id: `single_${Date.now()}`
    });
    
    console.log('Cloudinary upload result:', uploadResult);
    
    if (uploadResult.success) {
      res.status(200).json({
        message: "File uploaded successfully",
        path: uploadResult.url,
        filename: uploadResult.public_id
      });
    } else {
      console.error('Cloudinary upload failed:', uploadResult.error);
      console.error('Cloudinary config status:', {
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME ? 'present' : 'missing',
        api_key: process.env.CLOUDINARY_API_KEY ? 'present' : 'missing', 
        api_secret: process.env.CLOUDINARY_API_SECRET ? 'present' : 'missing'
      });
      res.status(500).json({ 
        message: "Failed to upload to Cloudinary", 
        error: uploadResult.error,
        debug: {
          hasCloudName: !!process.env.CLOUDINARY_CLOUD_NAME,
          hasApiKey: !!process.env.CLOUDINARY_API_KEY,
          hasApiSecret: !!process.env.CLOUDINARY_API_SECRET
        }
      });
    }
  } catch (error) {
    console.error("File upload error:", error);
    res.status(500).json({ message: "Error uploading file", error: error.message });
  }
});

// Upload texture file
app.post("/api/admin/textures/upload", authMiddleware, requireModelUploadPerm, uploadTexture.single('textureFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    // Return the file path relative to public directory
    const filePath = `/texture/${req.file.filename}`;
    res.status(200).json({
      message: "Texture uploaded successfully",
      path: filePath,
      filename: req.file.filename,
      originalName: req.file.originalname
    });
  } catch (error) {
    console.error("Texture upload error:", error);
    // Clean up uploaded file on error
    if (req.file) {
      const fileToDelete = path.join(__dirname, '../Frontend/public/texture', req.file.filename);
      if (fs.existsSync(fileToDelete)) {
        fs.unlinkSync(fileToDelete);
      }
    }
    res.status(500).json({ message: "Error uploading texture", error: error.message });
  }
});

// Upload texture file (for regular users)
app.post("/api/upload-texture", authMiddleware, uploadTexture.single('texture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    // Return the file path relative to public directory
    const filePath = `/texture/${req.file.filename}`;
    console.log(`📤 Texture uploaded successfully: ${filePath}`);

    res.status(200).json({
      message: "Texture uploaded successfully",
      path: filePath,
      filename: req.file.filename,
      originalName: req.file.originalname
    });
  } catch (error) {
    console.error("Texture upload error:", error);
    // Clean up uploaded file on error
    if (req.file) {
      const fileToDelete = path.join(__dirname, '../Frontend/public/texture', req.file.filename);
      if (fs.existsSync(fileToDelete)) {
        fs.unlinkSync(fileToDelete);
      }
    }
    res.status(500).json({ message: "Error uploading texture", error: error.message });
  }
});

// Upload preset images to Cloudinary (for admins)
app.post("/api/admin/upload-preset-images", authMiddleware, requireAdmin, uploadTexture.fields([
  { name: 'images', maxCount: 10 }
]), async (req, res) => {
  try {
    if (!req.files || !req.files.images || req.files.images.length === 0) {
      return res.status(400).json({ message: "No images uploaded" });
    }

    const { uploadToCloudinary } = require('./utils/cloudinaryUpload');
    const uploadedImages = [];

    for (const file of req.files.images) {
      try {
        console.log(`Uploading preset image: ${file.path}`);
        const uploadResult = await uploadToCloudinary(file.path, {
          folder: 'preset-images',
          public_id: `preset_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        });

        if (uploadResult.success) {
          uploadedImages.push({
            originalName: file.originalname,
            filename: file.filename,
            url: uploadResult.url,
            publicId: uploadResult.public_id,
            uploadedAt: new Date().toISOString()
          });
          console.log(`✅ Preset image uploaded to Cloudinary: ${uploadResult.url}`);
        } else {
          console.error(`❌ Failed to upload preset image:`, uploadResult.error);
        }
      } catch (uploadError) {
        console.error(`❌ Exception during preset image upload:`, uploadError.message);
      }
    }

    res.status(200).json({
      message: "Preset images uploaded successfully",
      images: uploadedImages,
      uploadedCount: uploadedImages.length,
      totalCount: req.files.images.length
    });
  } catch (error) {
    console.error("Preset images upload error:", error);
    res.status(500).json({ message: "Error uploading preset images", error: error.message });
  }
});

// Save model configuration (when file is already uploaded)
app.post("/api/admin/models", authMiddleware, requireModelUploadPerm, async (req, res) => {
  try {
    console.log('Incoming model POST body:', req.body);
    // Avoid shadowing the Node `path` module by renaming the incoming body field
    const { name, path: modelPath, configUrl, assets } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Model name is required" });
    }

    if (!modelPath) {
      return res.status(400).json({ message: "Model path is required" });
    }

    console.log('=== SAVE MODEL CONFIG DEBUG ===');
    console.log('Name:', name);
    console.log('Path:', path);
    console.log('ConfigUrl:', configUrl);
    console.log('Assets:', assets);
    console.log('===============================');


  // Extract filename from provided modelPath for storage
  const filename = (modelPath || '').toString().split('/').pop();

    // Sanitize configUrl: store as provided (supports external URLs), but trim spaces
    const sanitizedConfigUrl = typeof configUrl === 'string' ? configUrl.trim() : undefined;

    const newModel = new Model({
      name,
      displayName: name,
      path: modelPath,
      file: filename, // Store the filename as-is (Cloudinary URL or local path)
      type: 'glb',
      status: 'active', // Ensure model is active
      configUrl: sanitizedConfigUrl,
      assets: assets, // Add assets field
      uploadedBy: req.user._id,
      section: req.body.section || 'Upright Counter'
    });

    await newModel.save();
    // Placement/transform fields are managed via external config JSON; none are persisted here.
    await newModel.populate('uploadedBy', 'name email');

    // Thumbnail generation removed

    console.log('=== MODEL SAVED ===');
    console.log('Model ID:', newModel._id);
    console.log('Model metadata:', newModel.metadata);
    console.log('==================');

    // Send public viewer emails to all users
    try {
      const User = require('./models/User');

      // Get all users
      const users = await User.find({}).select('email name');
      console.log(`📧 Found ${users.length} users to notify`);

      if (users.length > 0) {
        const host = process.env.NODE_ENV === 'production'
          ? (process.env.FRONTEND_URL || 'https://frontendwestern.netlify.app')
          : (process.env.LOCAL_FRONTEND_URL || 'http://192.168.1.7:5173');
        const publicViewerUrl = `${host}/public-viewer.html?model=${newModel._id}`;

        // Send email to each user
        for (const user of users) {
          const subject = `New 3D Model Available: ${newModel.name}`;
          const html = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">New 3D Model Available!</h2>
              <p>Hello ${user.name || 'User'},</p>
              <p>A new 3D model has been added to our configurator: <strong>${newModel.name}</strong></p>
              <p>You can view and interact with this model by clicking the link below:</p>
              <p style="text-align: center; margin: 30px 0;">
                <a href="${publicViewerUrl}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">View 3D Model</a>
              </p>
              <p>The link will remain active for you to access this model anytime.</p>
              <p>Best regards,<br>The 3D Configurator Team</p>
            </div>
          `;

          const emailResult = await sendEmbedEmail(user.email, subject, html, publicViewerUrl);
          if (emailResult.success) {
            console.log(`✅ Email sent to ${user.email}`);
          } else {
            console.error(`❌ Failed to send email to ${user.email}:`, emailResult.error);
          }
        }
      }
    } catch (emailError) {
      console.error('❌ Error sending public viewer emails:', emailError);
      // Don't fail the model save if email sending fails
    }

    res.status(201).json({
      message: "Model saved successfully",
      model: newModel
    });
  } catch (error) {
    console.error("Save model error:", error, error.stack);
    res.status(500).json({ message: "Error saving model", error: error.message });
  }
});

// Update model
app.put("/api/admin/models/:id", authMiddleware, requireModelEditPerm, async (req, res) => {
  try {
    const { id } = req.params;
  const { name, displayName, type, status, file, path: filePath, configUrl, assets, section } = req.body;

  const updateData = {};
  if (typeof name === 'string') updateData.name = name;
  if (typeof displayName === 'string') updateData.displayName = displayName;
  if (typeof type === 'string') updateData.type = type;
  if (typeof status === 'string') updateData.status = status;
  if (typeof configUrl === 'string') updateData.configUrl = configUrl.trim();
  if (assets !== undefined) updateData.assets = assets; // Add assets field
  if (typeof section === 'string') updateData.section = section;
  // Allow updating file via either file or path (use filename only)
  if (typeof file === 'string') updateData.file = file.split('/').pop();
  if (typeof filePath === 'string') updateData.file = filePath.split('/').pop();

    console.log('=== UPDATE MODEL DEBUG ===');
    console.log('Incoming basic fields:', updateData);

    const model = await Model.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate('uploadedBy', 'name email');

    if (!model) {
      return res.status(404).json({ message: "Model not found" });
    }

    console.log('Persisted placement/transform fields after update:', {
      placementMode: model.placementMode,
      modelPosition: model.modelPosition,
      modelRotation: model.modelRotation,
      modelScale: model.modelScale
    });

    res.json({
      message: "Model updated successfully",
      model
    });
  } catch (error) {
    console.error("Update model error:", error);
    res.status(500).json({ message: "Error updating model", error: error.message });
  }
});

// Delete model
app.delete("/api/admin/models/:id", authMiddleware, requireModelDeletePerm, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('=== DELETE MODEL DEBUG ===');
    console.log('Model ID to delete:', id);
    
    const model = await Model.findById(id);
    console.log('Found model:', model ? `${model.name} (${model.file})` : 'null');

    if (!model) {
      return res.status(404).json({ message: "Model not found" });
    }

    const report = await performModelDeletion(model);
    console.log('Deletion report:', report);
    console.log('========================');

    res.json({ 
      message: "Model deleted successfully", 
      report 
    });
  } catch (error) {
    console.error("Delete model error:", error);
    res.status(500).json({ message: "Error deleting model", error: error.message });
  }
});

// Preview deletion (non-destructive)
app.get("/api/admin/models/:id/delete-preview", authMiddleware, requireModelDeletePerm, async (req, res) => {
  try {
    const { id } = req.params;
    const model = await Model.findById(id);
    
    if (!model) {
      return res.status(404).json({ message: "Model not found" });
    }

    // Collect candidate files
    const allAssets = collectAssetStrings(model);
    if (model.file) allAssets.models.add(model.file);
    if (model.configUrl && typeof model.configUrl === 'string' && model.configUrl.startsWith('/configs/')) {
      const configRel = model.configUrl.substring(9);
      allAssets.configs.add(configRel);
    }

    const baseDir = path.join(__dirname, '../Frontend/public');
    const candidates = [];

    for (const [type, files] of Object.entries(allAssets)) {
      const dirName = type === 'texture' ? 'texture' : type;
      const dirPath = path.join(baseDir, dirName);
      
      for (const file of files) {
        const filePath = path.join(dirPath, file);
        const exists = fs.existsSync(filePath);
        candidates.push({
          rel: `${type}/${file}`,
          fullPath: filePath,
          exists
        });
      }
    }

    res.json({
      model: { id: model._id, name: model.name, file: model.file },
      candidates,
      totalCandidates: candidates.length,
      existingFiles: candidates.filter(c => c.exists).length
    });
  } catch (error) {
    console.error("Preview error:", error);
    res.status(500).json({ message: "Error generating preview", error: error.message });
  }
});

// Force delete (aggressive cleanup)
app.post("/api/admin/models/:id/force-delete", authMiddleware, requireModelDeletePerm, async (req, res) => {
  try {
    const { id } = req.params;
    const model = await Model.findById(id);
    
    if (!model) {
      return res.status(404).json({ message: "Model not found" });
    }

    const report = await performModelDeletion(model);
    res.json({ 
      message: "Force delete completed", 
      report 
    });
  } catch (error) {
    console.error("Force delete error:", error);
    res.status(500).json({ message: "Error force deleting model", error: error.message });
  }
});

// Get model files list
app.get("/api/admin/models/files", authMiddleware, requireModelManager, async (req, res) => {
  try {
    const modelsPath = path.join(__dirname, '../Frontend/public/models');
    
    if (!fs.existsSync(modelsPath)) {
      return res.json([]);
    }

    const files = fs.readdirSync(modelsPath).filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.glb', '.gltf'].includes(ext);
    });

    const fileList = files.map(file => ({
      name: file,
      path: `/models/${file}`,
      size: fs.statSync(path.join(modelsPath, file)).size
    }));

    res.json(fileList);
  } catch (error) {
    console.error("Get model files error:", error);
    res.status(500).json({ message: "Error fetching model files", error: error.message });
  }
});

// Admin endpoint to get configurations for a specific user
app.get("/api/admin/user-configs/:userId", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { modelName } = req.query;
    
    const filter = { userId: userId };
    if (modelName) {
      filter.modelName = modelName;
    }

    const configs = await SavedConfiguration.find(filter)
      .sort({ updatedAt: -1 })
      .populate('userId', 'name email');
    
    res.json(configs);
  } catch (error) {
    console.error("Get user configurations error:", error);
    res.status(500).json({ message: "Error fetching user configurations", error: error.message });
  }
});

// Admin endpoint to delete any user's configuration
app.delete("/api/admin/user-configs/:configId", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const configId = req.params.configId;
    
    // Validate ObjectId early to avoid Mongoose CastErrors causing 500 responses
    if (!mongoose.Types.ObjectId.isValid(configId)) {
      console.warn(`Attempt to delete configuration with invalid id: ${configId}`);
      return res.status(400).json({ message: 'Invalid configuration id' });
    }

    // Find the configuration first to get its details for cleanup
    const config = await SavedConfiguration.findById(configId);
    if (!config) {
      return res.status(404).json({ message: "Configuration not found" });
    }

    // Delete the configuration
    await SavedConfiguration.findByIdAndDelete(configId);

    // Clean up texture files associated with this configuration
    try {
      await cleanupConfigTextures(configId);
    } catch (cleanupErr) {
      console.error('cleanupConfigTextures error for', configId, cleanupErr && (cleanupErr.stack || cleanupErr));
    }

    res.json({ message: "Configuration deleted successfully" });
  } catch (error) {
    console.error("Delete user configuration error:", error && (error.stack || error));
    res.status(500).json({ message: "Error deleting configuration", error: error.message || String(error) });
  }
});

// ==========================================
// SAVED CONFIGURATIONS API ENDPOINTS
// ==========================================

// Save user configuration
app.post("/api/configs/save", authMiddleware, async (req, res) => {
  try {
    const { name, description, modelName, configData, tags, isPublic } = req.body;
    
    if (!name || !modelName || !configData) {
      return res.status(400).json({ message: "Name, modelName, and configData are required" });
    }

    // Create the configuration first to get an ID
    const savedConfig = new SavedConfiguration({
      name,
      description: description || '',
      modelName,
      userId: req.user._id,
      configData,
      tags: tags || [],
      isPublic: isPublic || false,
      textureFiles: []
    });

    await savedConfig.save();
    
    // Process texture files if any textures are applied
    if (configData.textureSettings && Object.keys(configData.textureSettings).length > 0) {
      console.log('🔍 Processing texture files for configuration save:');
      console.log('configData.textureSettings:', configData.textureSettings);
      
      const textureFiles = [];
      
      for (const [textureKey, textureInfo] of Object.entries(configData.textureSettings)) {
        console.log(`🔍 Processing texture key: ${textureKey}`, textureInfo);
        
        // Check if we have a texture source that's a file path
        const textureSource = textureInfo.textureSource;
        console.log(`🔍 Texture source: ${textureSource}`);
        
        if (textureSource && (textureSource.startsWith('/texture/') || textureSource.startsWith('texture/'))) {
          try {
            console.log(`📂 Copying texture file: ${textureSource}`);
            
            // Copy the texture file to configuration storage
            const savedPath = await copyTextureForConfig(
              textureSource, 
              savedConfig._id.toString(), 
              textureKey
            );
            
            console.log(`✅ Texture copied to: ${savedPath}`);
            
            // Get file info
            const sourceFullPath = path.join(__dirname, '../Frontend/public', textureSource);
            const stats = await fs.promises.stat(sourceFullPath);
            
            textureFiles.push({
              originalName: path.basename(textureSource),
              savedPath: savedPath,
              configKey: textureKey,
              fileSize: stats.size,
              mimeType: `image/${path.extname(textureSource).substring(1)}`,
              uploadedAt: new Date()
            });
            
            // Update the texture info with the new path
            configData.textureSettings[textureKey].savedTexturePath = savedPath;
            
          } catch (error) {
            console.warn(`Failed to copy texture file for key ${textureKey}:`, error);
          }
        } else {
          console.log(`⏭️ Skipping texture ${textureKey}: not a file path (${textureSource})`);
        }
      }
      
      // Update the configuration with texture files and updated paths
      savedConfig.textureFiles = textureFiles;
      savedConfig.configData = configData;
      await savedConfig.save();
    }
    
    res.status(201).json({
      message: "Configuration saved successfully",
      config: savedConfig,
      textureFilesCopied: savedConfig.textureFiles.length
    });
  } catch (error) {
    console.error("Save configuration error:", error);
    res.status(500).json({ message: "Error saving configuration", error: error.message });
  }
});

// Get user's saved configurations
app.get("/api/configs/user", authMiddleware, async (req, res) => {
  try {
    const { modelName } = req.query;
    
    const filter = { userId: req.user._id };
    if (modelName) {
      filter.modelName = modelName;
    }

    const configs = await SavedConfiguration.find(filter)
      .sort({ updatedAt: -1 })
      .populate('userId', 'name email');
    
    res.json(configs);
  } catch (error) {
    console.error("Get user configurations error:", error);
    res.status(500).json({ message: "Error fetching configurations", error: error.message });
  }
});

// Get specific configuration by ID
app.get("/api/configs/:id", authMiddleware, async (req, res) => {
  try {
    const config = await SavedConfiguration.findOne({
      _id: req.params.id,
      $or: [
        { userId: req.user._id },  // User's own config
        { isPublic: true }         // Or public config
      ]
    }).populate('userId', 'name email');

    if (!config) {
      return res.status(404).json({ message: "Configuration not found or access denied" });
    }

    res.json(config);
  } catch (error) {
    console.error("Get configuration error:", error);
    res.status(500).json({ message: "Error fetching configuration", error: error.message });
  }
});

// Delete configuration
app.delete("/api/configs/:id", authMiddleware, async (req, res) => {
  try {
    const configId = req.params.id;
    // Validate ObjectId early to avoid Mongoose CastErrors causing 500 responses
    if (!mongoose.Types.ObjectId.isValid(configId)) {
      console.warn(`Attempt to delete configuration with invalid id: ${configId}`);
      return res.status(400).json({ message: 'Invalid configuration id' });
    }

    // Attempt to find-and-delete the saved configuration (owner must match)
    const config = await SavedConfiguration.findOneAndDelete({
      _id: configId,
      userId: req.user._id
    });

    if (!config) {
      return res.status(404).json({ message: "Configuration not found or access denied" });
    }

    // Clean up texture files associated with this configuration
    try {
      await cleanupConfigTextures(config._id.toString());
    } catch (cleanupErr) {
      console.error('cleanupConfigTextures error for', configId, cleanupErr && (cleanupErr.stack || cleanupErr));
    }

    res.json({ message: "Configuration deleted successfully" });
  } catch (error) {
    console.error("Delete configuration error:", error && (error.stack || error));
    res.status(500).json({ message: "Error deleting configuration", error: error.message || String(error) });
  }
});

// Serve configuration texture files
app.use('/config-textures', express.static(path.join(__dirname, '../Frontend/public/config-textures')));

// Public model endpoint (no authentication required)
app.get('/api/public/model/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ message: 'Model ID required' });
    
    const model = await Model.findOne({ _id: id, status: 'active' });
    if (!model) return res.status(404).json({ message: 'Model not found' });
    
    // Format model data similar to the main /api/models endpoint
    const meta = model.metadata || {};
    const uiWidgets = Array.isArray(model.uiWidgets) && model.uiWidgets.length
      ? model.uiWidgets
      : (Array.isArray(meta.uiWidgets) ? meta.uiWidgets : []);
    
    const lights = Array.isArray(model.lights) && model.lights.length
      ? model.lights
      : (Array.isArray(meta.lights) ? meta.lights : []);
    const hiddenInitially = Array.isArray(model.hiddenInitially) && model.hiddenInitially.length
      ? model.hiddenInitially
      : (Array.isArray(meta.hiddenInitially) ? meta.hiddenInitially : []);
    
    const normalizeAssetPath = (p) => {
      if (!p || typeof p !== 'string') return undefined;
      if (p.startsWith('http://') || p.startsWith('https://')) return p;
      const baseUrl = process.env.NODE_ENV === 'production' 
        ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
        : (process.env.LOCAL_BACKEND_URL || 'http://192.168.1.7:5000');
      if (p.startsWith('/models/')) return `${baseUrl}${p}`;
      return `${baseUrl}/models/${p}`;
    };
    
    const assetsRaw = model.assets || undefined;
    const assets = assetsRaw && typeof assetsRaw === 'object'
      ? Object.fromEntries(
          Object.entries(assetsRaw).map(([key, value]) => [key, normalizeAssetPathDev(value)])
        )
      : undefined;
    
    const normalizeConfigUrl = (u) => {
      if (!u || typeof u !== 'string') return undefined;
      if (u.startsWith('http://') || u.startsWith('https://')) return u;
      const baseUrl = process.env.NODE_ENV === 'production' 
        ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
        : (process.env.LOCAL_BACKEND_URL || 'http://192.168.1.7:5000');
      if (u.startsWith('/')) return `${baseUrl}${u}`;
      return `${baseUrl}/${u}`;
    };
    
    const payload = {
      id: model._id,
      name: model.name,
      displayName: model.displayName,
      file: model.path || `${process.env.NODE_ENV === 'production'
        ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
        : (process.env.LOCAL_BACKEND_URL || 'http://192.168.1.7:5000')}${model.file && model.file.startsWith('/models/') ? model.file : `/models/${model.file || ''}`}`,
      section: model.section || 'Upright Counter',
      type: model.type,
      configUrl: normalizeConfigUrl(model.configUrl || meta.configUrl) || undefined,
      interactionGroups: model.interactionGroups || [],
      metadata: { ...meta, uiWidgets },
      uiWidgets,
      lights,
      hiddenInitially,
      camera: model.camera || meta.camera || undefined,
      assets,
      presets: model.presets || undefined,
      placementMode: model.placementMode || 'autofit',
      modelPosition: Array.isArray(model.modelPosition) ? model.modelPosition : undefined,
      modelRotation: Array.isArray(model.modelRotation) ? model.modelRotation : undefined,
      modelScale: typeof model.modelScale === 'number' ? model.modelScale : undefined,
      readOnly: true
    };
    
    return res.json(payload);
  } catch (error) {
    console.error('Public model fetch error:', error);
    return res.status(500).json({ message: 'Internal error', error: error.message });
  }
});

// Legacy embed token endpoint (kept for backward compatibility)
app.get('/api/embed/resolve', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ message: 'token required' });
    const EmbedToken = require('./models/EmbedToken');
    const doc = await EmbedToken.findOne({ token, active: true }).populate('modelId');
    if (!doc || !doc.modelId) return res.status(404).json({ message: 'Invalid or expired token' });
    const model = doc.modelId;
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? (process.env.BACKEND_URL || 'https://threed-configurator-backend-7pwk.onrender.com')
      : (process.env.LOCAL_BACKEND_URL || 'http://192.168.1.7:5000');
    const payload = {
      id: model._id,
      name: model.name,
      displayName: model.displayName,
      file: model.file && (model.file.startsWith('http') || model.file.startsWith('https://')) ? model.file : `${baseUrl}${model.file && model.file.startsWith('/models/') ? model.file : `/models/${model.file || ''}`}`,
      configUrl: model.configUrl ? (model.configUrl.startsWith('http') ? model.configUrl : `${baseUrl}${model.configUrl}`) : undefined,
      assets: model.assets || {},
      metadata: model.metadata || {},
      readOnly: true
    };
    return res.json({ success: true, model: payload });
  } catch (error) {
    console.error('Embed resolve error:', error);
    return res.status(500).json({ message: 'Internal error', error: error.message });
  }
});

// Admin: list embed tokens for a model
app.get('/api/admin/models/:id/embed-tokens', authMiddleware, requireModelManager, async (req, res) => {
  try {
    const modelId = req.params.id;
    const EmbedToken = require('./models/EmbedToken');
    const tokens = await EmbedToken.find({ modelId }).populate('userId', 'email name');
    const host = process.env.NODE_ENV === 'production'
      ? (process.env.FRONTEND_URL || 'https://frontendwestern.netlify.app')
      : (process.env.LOCAL_FRONTEND_URL || 'http://localhost:5173');
    const out = tokens.map(t => ({ token: t.token, user: t.userId, active: t.active, url: `${host}/embed?token=${t.token}`, createdAt: t.createdAt }));
    res.json(out);
  } catch (error) {
    console.error('Error fetching embed tokens:', error);
    res.status(500).json({ message: 'Error fetching embed tokens', error: error.message });
  }
});

// Dev-only mailer status endpoint (unauthenticated) — only enabled when not in production
app.get('/api/debug/mailer-status', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ ok: false, message: 'Not allowed in production' });
  }
  const { getMailerStatus } = require('./utils/mailer');
  const status = typeof getMailerStatus === 'function' ? getMailerStatus() : null;
  return res.json({ ok: true, status });
});

// Start server on network IP
const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0'; // Always listen on all interfaces

const server = app.listen(PORT, HOST, () => {
  console.log(`🚀 Backend running on http://${HOST}:${PORT}`);
  console.log(`🌐 Local access: http://localhost:${PORT}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`🌐 Network access: http://192.168.1.7:${PORT}`);
    console.log(`🌐 Health check: http://192.168.1.7:${PORT}/api/health`);
  }
});

// Handle deployment timeouts
server.timeout = 30000;

// Express global error handler (handles request aborted and other body parse errors)
app.use((err, req, res, next) => {
  if (err) {
    // Quietly handle very common client-side aborts to avoid console spam
    if (err.message === 'request aborted') {
      return res.status(400).json({ message: err.message });
    }
    if (err.type === 'entity.too.large') {
      console.warn('⚠️ Request body too large');
      return res.status(413).json({ message: 'Payload too large' });
    }
    console.error('Unhandled error:', err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
  next();
});

// Configure multer for JSON config uploads
const configsStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, '../Frontend/public/configs');
    // Directory creation is now handled by ensureDirectoriesExist() on startup
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    // Preserve original extension
    cb(null, 'config-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const uploadConfig = multer({
  storage: configsStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB for JSON configs
  fileFilter: function (req, file, cb) {
    const allowed = ['.json'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only JSON files are allowed for configs'), false);
  }
});

// Upload config JSON
app.post('/api/upload-config', authMiddleware, requireModelManager, uploadConfig.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No config file uploaded' });
    }

    const filePath = `/configs/${req.file.filename}`;
    console.log(`Config uploaded: ${filePath}`);
    res.status(200).json({ message: 'Config uploaded successfully', path: filePath, filename: req.file.filename });
  } catch (error) {
    console.error('Config upload error:', error);
    if (req.file) {
      const fileToDelete = path.join(__dirname, '../Frontend/public/configs', req.file.filename);
      if (fs.existsSync(fileToDelete)) fs.unlinkSync(fileToDelete);
    }
    res.status(500).json({ message: 'Error uploading config', error: error.message });
  }
});

// Admin-only: clear all activity logs (destructive) - use with caution
app.delete('/api/activity/clear', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    const result = await ActivityLog.deleteMany({});
    console.log(`Admin ${req.user.email} cleared activity logs, deletedCount=${result.deletedCount}`);
    // Record deletion action in activity log chain
    try {
      await appendActivityLogEntry({
        user: req.user,
        action: 'ACTIVITY_CLEAR_GLOBAL',
        details: { deletedCount: result.deletedCount },
        visibility: 'admin'
      });
    } catch (err) {
      console.error('Failed to record deletion audit entry:', err);
    }
    return res.json({ message: 'Activity logs cleared', deletedCount: result.deletedCount });
  } catch (err) {
    console.error('Error clearing activity logs:', err);
    return res.status(500).json({ message: 'Error clearing activity logs', error: err.message });
  }
});

// Admin-only: clear activity logs for a specific userId
app.delete('/api/activity/clear/:userId', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    const { userId } = req.params;
    if (!userId) return res.status(400).json({ message: 'Missing userId' });
    const result = await ActivityLog.deleteMany({ userId });
    console.log(`Admin ${req.user.email} cleared activity logs for user=${userId}, deletedCount=${result.deletedCount}`);
    // Record deletion action in activity log chain (per-user)
    try {
      await appendActivityLogEntry({
        user: req.user,
        action: 'ACTIVITY_CLEAR_USER',
        details: { targetUserId: userId, deletedCount: result.deletedCount },
        visibility: 'admin'
      });
    } catch (err) {
      console.error('Failed to record per-user deletion audit entry:', err);
    }
    return res.json({ message: 'Activity logs cleared for user', deletedCount: result.deletedCount });
  } catch (err) {
    console.error('Error clearing activity logs for user:', err);
    return res.status(500).json({ message: 'Error clearing activity logs', error: err.message });
  }
});

// Export activity logs as NDJSON or CSV (streaming)
app.get('/api/activity/export', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

    const format = (req.query.format || 'ndjson').toLowerCase(); // 'ndjson' or 'csv'
    const compress = req.query.compress === 'true';
    const { startDate, endDate, userId, action } = req.query;

    const filter = {};
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = new Date(startDate);
      if (endDate) filter.timestamp.$lte = new Date(endDate);
    }
    if (userId) filter.userId = userId;
    if (action) filter.action = new RegExp(action, 'i');

    // Set headers
    const filenameBase = `activity-${new Date().toISOString().slice(0,10)}`;
    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filenameBase}.csv${compress?'.gz':''}"`);
    } else {
      res.setHeader('Content-Type', 'application/x-ndjson');
      res.setHeader('Content-Disposition', `attachment; filename="${filenameBase}.ndjson${compress?'.gz':''}"`);
    }

    // Use gzip if requested
    let stream = ActivityLog.find(filter).sort({ timestamp: 1 }).cursor();
    const { pipeline } = require('stream');
    const zlib = require('zlib');

    // Write stream helper
    const out = res;

    // Count rows for audit
    let rowCount = 0;

    if (compress) {
      res.setHeader('Content-Encoding', 'gzip');
    }

    // Streaming handler
    if (format === 'csv') {
      // CSV header
      const header = 'id,timestamp,actor_id,actor_email,actor_name,action,modelName,partName,ipAddress,hash,previousHash,details\n';
      if (compress) out.write(zlib.gzipSync(header)); else out.write(header);

      for await (const doc of stream) {
        const row = [
          doc._id,
          doc.timestamp?.toISOString() || '',
          doc.userId || '',
          (doc.userEmail || '').replace(/\"/g, '"'),
          (doc.userName || '').replace(/\"/g, '"'),
          (doc.action || ''),
          (doc.modelName || ''),
          (doc.partName || ''),
          (doc.ipAddress || ''),
          (doc.hash || ''),
          (doc.previousHash || ''),
          JSON.stringify(doc.details || {})
        ].map(v => {
          if (v === null || v === undefined) return '';
          const s = String(v).replace(/"/g, '""');
          // wrap in quotes if contains comma or newline
          return /[",\n]/.test(s) ? '"' + s + '"' : s;
        }).join(',') + '\n';

        if (compress) out.write(zlib.gzipSync(row)); else out.write(row);
        rowCount++;
        // allow client to drain
        await new Promise(resolve => setImmediate(resolve));
      }
    } else {
      // NDJSON
      for await (const doc of stream) {
        const obj = {
          _id: doc._id,
          timestamp: doc.timestamp,
          actor_id: doc.userId,
          actor_email: doc.userEmail,
          actor_name: doc.userName,
          action: doc.action,
          modelName: doc.modelName,
          partName: doc.partName,
          ipAddress: doc.ipAddress,
          hash: doc.hash,
          previousHash: doc.previousHash,
          details: doc.details || {}
        };
        const line = JSON.stringify(obj) + '\n';
        if (compress) out.write(zlib.gzipSync(line)); else out.write(line);
        rowCount++;
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    // After streaming, append an ActivityLog for the export request
    try {
      await appendActivityLogEntry({
        user: req.user,
        action: 'ACTIVITY_EXPORT',
        details: { format, filters: { startDate, endDate, userId, action }, rowCount },
        visibility: 'admin'
      });
    } catch (err) {
      console.error('Failed to record export audit entry:', err);
    }

    // End response
    if (!res.writableEnded) res.end();
  } catch (err) {
    console.error('Activity export error:', err);
    if (!res.headersSent) res.status(500).json({ message: 'Error exporting activity logs', error: err.message });
  }
});

// Cloudinary cleanup endpoints
app.get('/api/admin/cloudinary/files', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { getCloudinaryFiles } = require('./utils/cloudinaryCleanup');
    const files = await getCloudinaryFiles();
    res.json({ files, count: files.length });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching Cloudinary files', error: error.message });
  }
});

app.post('/api/admin/cloudinary/cleanup', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { cleanupOrphanedFiles } = require('./utils/cloudinaryCleanup');
    const report = await cleanupOrphanedFiles(Model);
    res.json(report);
  } catch (error) {
    res.status(500).json({ message: 'Error cleaning up files', error: error.message });
  }
});

app.delete('/api/admin/cloudinary/file/:publicId', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { deleteCloudinaryFile } = require('./utils/cloudinaryCleanup');
    const publicId = decodeURIComponent(req.params.publicId);
    const result = await deleteCloudinaryFile(publicId);
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: 'Error deleting file', error: error.message });
  }
});

// Note: User creation is now handled by /routes/adminDashboard.js with proper permission-based access control

// SSE stream endpoint for real-time events (permissions updates etc.)
app.get('/api/stream', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;
    if (!token) return res.status(401).end('No token');
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).end('Invalid token'); }
    const userId = decoded.id;

    // Set headers for SSE
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });

    // Send a ping so client knows connection is active
    res.write('event: connected\n');
    res.write(`data: ${JSON.stringify({ message: 'connected' })}\n\n`);

    if (!sseClients.has(userId)) sseClients.set(userId, new Set());
    sseClients.get(userId).add(res);

    req.on('close', () => {
      const set = sseClients.get(userId);
      if (set) {
        set.delete(res);
        if (!set.size) sseClients.delete(userId);
      }
    });
  } catch (error) {
    console.error('SSE stream error:', error);
    res.status(500).end();
  }
});