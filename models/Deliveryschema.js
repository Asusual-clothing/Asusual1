const mongoose = require('mongoose');

const deliveryCostSchema = new mongoose.Schema({
  cost: {
    type: Number,
    required: true,
    default: 0
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('DeliveryCost', deliveryCostSchema);
