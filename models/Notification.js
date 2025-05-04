const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
    notification: {
      type: String,
      default: '',
      trim: true
    }
  });
  

module.exports = mongoose.model('Notification',notificationSchema);