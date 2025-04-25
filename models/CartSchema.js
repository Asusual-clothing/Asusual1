const mongoose = require('mongoose');

const CartSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  items: [
    {
      product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: false
      },
      quantity: {
        type: Number,
        required: true
      },
      size: {
        type: String,
        required: true
      }
    }
  ],
  // Add coupon-related fields
  appliedCoupon: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Coupon'
  },
  discountAmount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true,
  strictPopulate: false // To avoid population errors
});

module.exports = mongoose.model('Cart', CartSchema);