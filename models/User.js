const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['employee', 'admin', 'superadmin', 'manager', 'assistantmanager', 'custom'],
    default: 'employee'
  },
  customRoleName: {
    type: String,
    default: ''
  },
  permissions: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  lastLogin: {
    type: Date
  },
  // OTP fields for password reset
  resetOtp: {
    type: String,
  },
  resetOtpExpires: {
    type: Date,
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  return userObject;
};

// Export model without recompiling if already compiled (prevents OverwriteModelError)
module.exports = mongoose.models && mongoose.models.User ? mongoose.models.User : mongoose.model('User', userSchema);