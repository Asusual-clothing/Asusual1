const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: { type: String },
  resetTokenExpiration: { type: Date },
  createdAt: { type: Date, default: Date.now },
    phone: { type: String },
    
  });

  module.exports = mongoose.model('User', UserSchema);