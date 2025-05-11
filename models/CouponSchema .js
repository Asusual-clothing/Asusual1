const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  discountType: {
    type: String,
    enum: ['percentage', 'flat'], // Only allow these two types
    required: true
  },
  discountValue: { type: Number, required: true }, // percentage or flat value
  expiryDate: { type: Date, required: true },
  active: { type: Boolean, default: true },
  useonce: {type: Boolean, default: false},
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Coupon', CouponSchema);
