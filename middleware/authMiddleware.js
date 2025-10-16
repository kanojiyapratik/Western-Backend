// middleware/authMiddleware.js - improved version
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const authMiddleware = (allowedRoles = [], requiredPermission = null) => {
  return async (req, res, next) => {
    try {
      let token;
      
      if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];
      }
      
      if (!token) {
        return res.status(401).json({ message: "No authentication token provided" });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select("-password");
      
      if (!user) {
        return res.status(401).json({ message: "User not found" });
      }
      
      // Check role if specific roles are required
      const hasRole = allowedRoles.length === 0 || allowedRoles.includes(user.role);
      
      // Check permission if required
      const hasPermission = !requiredPermission || (user.permissions && user.permissions[requiredPermission]);
      
      // Debug logging for permission issues
      if (requiredPermission) {
        console.log('=== AUTH MIDDLEWARE DEBUG ===');
        console.log('User:', user.name, 'Role:', user.role);
        console.log('Required roles:', allowedRoles);
        console.log('Required permission:', requiredPermission);
        console.log('Has role?', hasRole);
        console.log('Has permission?', hasPermission);
        console.log('Specific permission value:', user.permissions?.[requiredPermission]);
      }
      
      // Allow access if user has required role OR required permission
      if (!hasRole && !hasPermission) {
        console.log('=== ACCESS DENIED ===');
        console.log('User:', user.name, 'tried to access with roles:', allowedRoles, 'permission:', requiredPermission);
        console.log('User role:', user.role, 'hasRole:', hasRole);
        console.log('Required permission:', requiredPermission, 'hasPermission:', hasPermission);
        return res.status(403).json({ message: "Access denied: insufficient permissions" });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error("Auth middleware error:", error);
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
};

module.exports = authMiddleware;