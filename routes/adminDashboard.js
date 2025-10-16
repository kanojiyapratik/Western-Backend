// routes/adminDashboard.js
const express = require("express");
const router = express.Router();
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");

// Get all users (admin/superadmin only or userManagement permission)
router.get("/users", authMiddleware(["admin", "superadmin"], "userManagement"), async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    console.log('🔍 DEBUG: Total users in DB:', users.length);
    console.log('🔍 DEBUG: User emails:', users.map(u => u.email));
    console.log('🔍 DEBUG: Database URI:', process.env.MONGO_URI ? 'Atlas (production)' : 'localhost');
    console.log('🔍 DEBUG: All users:', users.map(u => ({ name: u.name, email: u.email, role: u.role })));
    console.log('🔍 DEBUG: Current user ID being filtered:', req.user._id.toString());
    console.log('🔍 DEBUG: Users after filtering:', users.filter(user => user._id.toString() !== req.user._id.toString()).map(u => ({ name: u.name, email: u.email, role: u.role })));
    // Filter out the current user to prevent self-editing
    const filteredUsers = users.filter(user => user._id.toString() !== req.user._id.toString());
    res.json(filteredUsers);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users", error: error.message });
  }
});

// Update user permissions
router.put("/users/:id/permissions", authMiddleware(["admin"], "userManageEdit"), async (req, res) => {
  try {
    const { permissions, role, customRoleName } = req.body;
    console.log('=== BACKEND UPDATE DEBUG ===');
    console.log('User ID:', req.params.id);
    console.log('Received full request body:', req.body);
    console.log('Received permissions object:', JSON.stringify(permissions, null, 2));
    console.log('User management permissions received:', {
      userManagement: permissions?.userManagement,
      userManageCreate: permissions?.userManageCreate,
      userManageEdit: permissions?.userManageEdit,
      userManageDelete: permissions?.userManageDelete
    });
    console.log('Role:', role);
    
    // Check if permissions object contains the user management permissions
    const userMgmtKeys = ['userManagement', 'userManageCreate', 'userManageEdit', 'userManageDelete'];
    const userMgmtPerms = {};
    userMgmtKeys.forEach(key => {
      if (permissions && permissions.hasOwnProperty(key)) {
        userMgmtPerms[key] = permissions[key];
      }
    });
    console.log('Extracted user management permissions:', userMgmtPerms);
    
    const updateFields = { 
      $set: { 
        permissions,
        role,
        customRoleName: customRoleName || ''
      }
    };
    
    console.log('MongoDB update fields:', JSON.stringify(updateFields, null, 2));
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true, select: "-password", runValidators: true }
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    console.log('=== POST-SAVE DEBUG ===');
    console.log('Saved user full object:', JSON.stringify(user.toObject(), null, 2));
    console.log('Saved user permissions:', JSON.stringify(user.permissions, null, 2));
    console.log('Saved user management permissions:', {
      userManagement: user.permissions?.userManagement,
      userManageCreate: user.permissions?.userManageCreate,
      userManageEdit: user.permissions?.userManageEdit,
      userManageDelete: user.permissions?.userManageDelete
    });
    
    // Also manually check the database to see what was actually saved
    const dbUser = await User.findById(req.params.id).select('-password');
    console.log('=== DIRECT DB CHECK ===');
    console.log('DB user permissions:', JSON.stringify(dbUser.permissions, null, 2));
    console.log('DB user management permissions:', {
      userManagement: dbUser.permissions?.userManagement,
      userManageCreate: dbUser.permissions?.userManageCreate,
      userManageEdit: dbUser.permissions?.userManageEdit,
      userManageDelete: dbUser.permissions?.userManageDelete
    });
    
    res.json({ message: "Permissions updated successfully", user });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ message: "Error updating user", error: error.message });
  }
});

// Toggle user active status
// Note: Active/Inactive user status removed from the system.

// Delete user
router.delete("/users/:id", authMiddleware(["admin"], "userManageDelete"), async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user", error: error.message });
  }
});

// Create new user (admin only or userManageCreate permission)
router.post("/users", authMiddleware(["admin"], "userManageCreate"), async (req, res) => {
  try {
    const { name, email, password, role = 'employee', permissions = {} } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email and password are required" });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ message: "User already exists" });

    const user = await User.create({
      name,
      email: email.toLowerCase().trim(),
      password, // let the model middleware handle hashing
      role,
      permissions
    });

    res.status(201).json({ message: 'User created', user: { ...user.toObject(), password: undefined } });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

module.exports = router;