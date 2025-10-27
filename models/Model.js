const mongoose = require('mongoose');

const ModelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  displayName: { type: String },
  path: { type: String, required: true },
  file: { type: String },
  configUrl: { type: String },
  section: { type: String, required: false, default: 'Upright Counter' },
  type: { type: String },
  status: { type: String, default: 'active' },
  assets: { type: mongoose.Schema.Types.Mixed },
  metadata: { type: mongoose.Schema.Types.Mixed },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  thumbnail: { type: String }, // Thumbnail filename
  camera: { type: mongoose.Schema.Types.Mixed },
  lights: { type: [mongoose.Schema.Types.Mixed], default: [] },
  hiddenInitially: { type: [String], default: [] },
  uiWidgets: { type: [mongoose.Schema.Types.Mixed], default: [] },
  presets: { type: mongoose.Schema.Types.Mixed },
  // Preset images for easy reference in configurations
  presetImages: [{
    originalName: { type: String },
    filename: { type: String },
    url: { type: String, required: true },
    publicId: { type: String },
    uploadedAt: { type: Date, default: Date.now }
  }],
  placementMode: { type: String, default: 'autofit' },
  modelPosition: { type: [Number], default: [0, 0.5, 0] },
  modelRotation: { type: [Number], default: [0, 0, 0] },
  modelScale: { type: Number, default: 1 },
  interactionGroups: { type: [mongoose.Schema.Types.Mixed], default: [] },
  shadows: { type: mongoose.Schema.Types.Mixed, default: { enabled: true, position: [0, -0.5, 0], opacity: 0.4, scale: 10, blur: 2.5, far: 4.5, resolution: 256, color: "#000000" } }
}, { timestamps: true });

module.exports = mongoose.model('Model', ModelSchema);
