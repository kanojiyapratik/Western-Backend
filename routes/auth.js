// routes/auth.js
const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { sendEmbedEmail } = require("../utils/mailer");
const authMiddleware = require("../middleware/authMiddleware");

// Helper to generate 6-digit OTP
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

router.post("/register", async (req, res) => {
  try {
    // Prevent public self-registration unless explicitly allowed via env var
    if (process.env.ALLOW_SELF_REGISTRATION !== 'true') {
      return res.status(403).json({ message: "Self-registration is disabled. Please contact your administrator." });
    }
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user with default permissions (only canRotate: true)
    const user = new User({
      name,
      email,
      password: hashedPassword,
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
    
    await user.save();
    
    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    
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
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: "Invalid password" });
    }
    
    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    
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
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// Get current user
router.get("/me", authMiddleware(["admin", "user"]), async (req, res) => {
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

// Request password reset (send OTP to email)
router.post('/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Invalid email' });

    const otp = generateOtp();
    user.resetOtp = otp;
    // expire in 15 minutes
    user.resetOtpExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    // send OTP email (html simple)
    const subject = 'Your password reset code';
    const html = `<p>Your password reset code is <strong>${otp}</strong>. It expires in 15 minutes.</p>`;
    const emailResult = await sendEmbedEmail(user.email, subject, html);

    if (!emailResult.success) {
      return res.status(500).json({ message: 'Failed to send reset email', error: emailResult.error });
    }

    res.json({ message: 'OTP sent to email' });
  } catch (error) {
    res.status(500).json({ message: 'Error requesting password reset', error: error.message });
  }
});

// Reset password using OTP
router.post('/reset-password', async (req, res) => {
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
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
});

// Change password when authenticated (provide currentPassword and newPassword)
router.post('/change-password', authMiddleware(["admin", "user"]), async (req, res) => {
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
    res.status(500).json({ message: 'Error changing password', error: error.message });
  }
});

module.exports = router;