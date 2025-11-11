const mongoose = require('mongoose');

const permissionRequestSchema = new mongoose.Schema({
  requesterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  requestedPermissions: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  justification: {
    type: String,
    required: true,
    maxlength: 500
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  requestedBy: {
    type: String,
    enum: ['self', 'manager', 'admin'],
    default: 'self'
  },
  adminResponse: {
    type: String,
    maxlength: 500
  },
  respondedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  respondedAt: {
    type: Date
  },
  notificationSent: {
    type: Boolean,
    default: false
  },
  emailSent: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Index for efficient queries
permissionRequestSchema.index({ requesterId: 1, status: 1 });
permissionRequestSchema.index({ targetId: 1, status: 1 });
permissionRequestSchema.index({ status: 1, createdAt: -1 });

// Export model
module.exports = mongoose.models && mongoose.models.PermissionRequest ? 
  mongoose.models.PermissionRequest : 
  mongoose.model('PermissionRequest', permissionRequestSchema);