const mongoose = require('mongoose');

const embedTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  modelId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Model',
    required: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
  }
});

// Index for efficient token lookup
embedTokenSchema.index({ token: 1, active: 1 });

// Auto-cleanup expired tokens
embedTokenSchema.pre('find', function() {
  this.where({ expiresAt: { $gt: new Date() } });
});

module.exports = mongoose.model('EmbedToken', embedTokenSchema);