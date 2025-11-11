const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const PermissionRequest = require("../models/PermissionRequest");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
const { sendEmbedEmail } = require("../utils/mailer");

// Get all permission requests for admin/superadmin
router.get("/admin", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    const { status = "all" } = req.query;

    const filter = {};
    if (status && status !== 'all') {
      filter.status = status;
    }

    const requests = await PermissionRequest.find(filter)
      .populate('requesterId', 'name email role')
      .populate('targetId', 'name email role')
      .populate('respondedBy', 'name email')
      .sort({ createdAt: -1 });

    res.json(requests);
  } catch (error) {
    console.error('Error fetching permission requests:', error);
    res.status(500).json({ message: "Error fetching requests", error: error.message });
  }
});

// Get requests for current user
router.get("/my-requests", authMiddleware(["admin", "user"]), async (req, res) => {
  try {
    const { status = "all" } = req.query;

    const filter = { requesterId: req.user._id };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const requests = await PermissionRequest.find(filter)
      .populate('targetId', 'name email role')
      .populate('respondedBy', 'name email')
      .sort({ createdAt: -1 });

    res.json(requests);
  } catch (error) {
    console.error('Error fetching user requests:', error);
    res.status(500).json({ message: "Error fetching requests", error: error.message });
  }
});

// Get pending requests count for admin/superadmin
router.get("/admin/pending-count", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    const count = await PermissionRequest.countDocuments({ 
      status: 'pending',
      notificationSent: false
    });
    res.json({ count });
  } catch (error) {
    console.error('Error fetching pending count:', error);
    res.status(500).json({ message: "Error fetching count", error: error.message });
  }
});

// Create a new permission request
router.post("/", authMiddleware(["admin", "user"]), async (req, res) => {
  try {
    const { targetId, requestedPermissions, justification, requestedBy = 'self' } = req.body;

    // Validate required fields
    if (!targetId || !requestedPermissions || !justification) {
      return res.status(400).json({ message: "Target ID, requested permissions, and justification are required" });
    }

    // Validate target user exists
    const targetUser = await User.findById(targetId);
    if (!targetUser) {
      return res.status(404).json({ message: "Target user not found" });
    }

    // Check if requester has permission to make requests for this target
    const requesterHierarchy = { 'employee': 1, 'assistantmanager': 2, 'manager': 3, 'admin': 4, 'superadmin': 5 };
    const targetHierarchy = requesterHierarchy[targetUser.role] || 1;
    const requesterLevel = requesterHierarchy[req.user.role] || 1;

    if (requestedBy === 'self' && targetId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "You can only request permissions for yourself" });
    }

    if (requestedBy === 'manager' && !(req.user.role === 'manager' || req.user.role === 'admin' || req.user.role === 'superadmin')) {
      return res.status(403).json({ message: "Only managers and above can request permissions for others" });
    }

    if (requestedBy === 'admin' && !(req.user.role === 'admin' || req.user.role === 'superadmin')) {
      return res.status(403).json({ message: "Only admins can request permissions as admin" });
    }

    // Check if there's already a pending request for the same permissions
    const existingRequest = await PermissionRequest.findOne({
      requesterId: req.user._id,
      targetId,
      status: 'pending',
      'requestedPermissions': requestedPermissions
    });

    if (existingRequest) {
      return res.status(400).json({ message: "A similar request is already pending" });
    }

    // Create the request
    const permissionRequest = new PermissionRequest({
      requesterId: req.user._id,
      targetId,
      requestedPermissions,
      justification,
      requestedBy
    });

    await permissionRequest.save();

    // Get admin users to notify
    const adminUsers = await User.find({ 
      role: { $in: ['admin', 'superadmin'] },
      _id: { $ne: req.user._id }
    });

    // Send email notifications to admins
    for (const admin of adminUsers) {
      try {
        const requester = await User.findById(req.user._id);
        const html = `
          <h2>New Permission Request</h2>
          <p><strong>Requester:</strong> ${requester.name} (${requester.email})</p>
          <p><strong>Target User:</strong> ${targetUser.name} (${targetUser.email})</p>
          <p><strong>Requested By:</strong> ${requestedBy}</p>
          <p><strong>Requested Permissions:</strong></p>
          <ul>
            ${Object.entries(requestedPermissions).map(([key, value]) => 
              `<li>${key}: ${value ? 'Enable' : 'Disable'}</li>`
            ).join('')}
          </ul>
          <p><strong>Justification:</strong></p>
          <p>${justification}</p>
          <p><a href="${process.env.ADMIN_PANEL_URL || 'http://localhost:3000/admin'}/permission-requests">Review Request</a></p>
        `;

        await sendEmbedEmail(admin.email, 'New Permission Request', html);
      } catch (emailError) {
        console.error('Error sending email to admin:', admin.email, emailError);
      }
    }

    res.status(201).json(permissionRequest);
  } catch (error) {
    console.error('Error creating permission request:', error);
    res.status(500).json({ message: "Error creating request", error: error.message });
  }
});

// Mark a permission request as resolved
router.put("/:requestId/resolve", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    const { requestId } = req.params;
    const { status, adminResponse = '' } = req.body;
    
    // Validate status
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: "Status must be 'approved' or 'rejected'" });
    }
    
    // Find and update the request
    const permissionRequest = await PermissionRequest.findById(requestId);
    if (!permissionRequest) {
      return res.status(404).json({ message: "Request not found" });
    }
    
    // Update the request to the specific decision
    permissionRequest.status = status; // 'approved' | 'rejected'
    permissionRequest.adminResponse = adminResponse;
    permissionRequest.respondedBy = req.user._id;
    permissionRequest.respondedAt = new Date();

    // Try saving; if the schema still has legacy enum (pending/resolved), fall back gracefully
    try {
      await permissionRequest.save();
    } catch (saveErr) {
      if (saveErr && saveErr.name === 'ValidationError' && saveErr.errors && saveErr.errors.status) {
        console.warn('PermissionRequest status enum mismatch, falling back to legacy "resolved"');
        permissionRequest.status = 'resolved';
        await permissionRequest.save();
      } else {
        throw saveErr;
      }
    }

    console.log('Request resolved:', {
      requestId,
      status,
      adminUser: req.user.email,
      timestamp: new Date().toISOString()
    });

    res.json({
      message: `Request ${status} successfully`,
      requestId,
      status,
      adminUser: req.user.email,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error resolving request:', error);
    res.status(500).json({
      message: "Error resolving request",
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Mark notifications as sent
router.put("/:requestId/mark-notified", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    const { requestId } = req.params;

    const permissionRequest = await PermissionRequest.findById(requestId);
    if (!permissionRequest) {
      return res.status(404).json({ message: "Request not found" });
    }

    permissionRequest.notificationSent = true;
    await permissionRequest.save();

    res.json({ message: "Request marked as notified" });
  } catch (error) {
    console.error('Error marking request as notified:', error);
    res.status(500).json({ message: "Error marking request as notified", error: error.message });
  }
});

// Test endpoint to check if route is working
router.get("/test", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    console.log('Test endpoint called by:', req.user.email);
    const count = await PermissionRequest.countDocuments();
    console.log('Total permission requests in database:', count);
    res.json({ message: "Permission requests route is working", user: req.user.email, count });
  } catch (error) {
    console.error('Test endpoint error:', error);
    res.status(500).json({ message: "Test endpoint error", error: error.message });
  }
});
// Delete a permission request
router.delete("/:requestId", authMiddleware(["admin", "user"]), async (req, res) => {
  try {
    const { requestId } = req.params;
    const token = req.headers.authorization?.replace('Bearer ', '');

    // Get the request to verify ownership
    const request = await PermissionRequest.findById(requestId);
    if (!request) {
      return res.status(404).json({ message: "Request not found" });
    }

    // Check if user owns this request or is admin/superadmin
    const isOwner = request.requesterId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: "You can only delete your own requests" });
    }

    // Check if request is already resolved
    if (request.status === 'resolved') {
      return res.status(400).json({ message: "Cannot delete resolved requests" });
    }

    // Delete the request
    await PermissionRequest.findByIdAndDelete(requestId);

    res.json({ message: "Request deleted successfully" });
  } catch (error) {
    console.error('Error deleting permission request:', error);
    res.status(500).json({ message: "Error deleting request", error: error.message });
  }
});

module.exports = router;

// Debug specific request
router.get("/debug/:requestId", authMiddleware(["admin", "superadmin"]), async (req, res) => {
  try {
    console.log('Debug request ID:', req.params.requestId);
    const { requestId } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      return res.status(400).json({ message: "Invalid ObjectId" });
    }
    
    const request = await PermissionRequest.findById(requestId);
    console.log('Debug request found:', !!request);
    
    if (request) {
      console.log('Request data:', {
        _id: request._id,
        status: request.status,
        requesterId: request.requesterId,
        targetId: request.targetId,
        createdAt: request.createdAt,
        requestedPermissions: request.requestedPermissions,
        justification: request.justification
      });
    } else {
      console.log('No document found with ID:', requestId);
    }
    
    res.json({ found: !!request, request });
  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;