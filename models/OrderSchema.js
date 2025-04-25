const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  cart: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Cart',
    required: true
  },
  items: [{
    product: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'Product', 
      required: true 
    },
    quantity: { 
      type: Number, 
      required: true,
      min: [1, 'Quantity cannot be less than 1']
    },
    size: {
      type: String,
      required: true
    },
    priceAtPurchase: { 
      type: Number, 
      required: true,
      min: [0, 'Price cannot be negative']
    }
  }],
  subtotal: { 
    type: Number, 
    required: true,
    min: [0, 'Subtotal cannot be negative']
  },
  discountAmount: {
    type: Number,
    default: 0
  },
  shippingFee: {
    type: Number,
    required: true,
    default: 0
  },
  totalAmount: { 
    type: Number, 
    required: true,
    min: [0, 'Total amount cannot be negative']
  },
  status: { 
    type: String, 
    enum: ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled', 'Refunded'], 
    default: 'Pending',
    index: true
  },
  paymentMethod: { 
    type: String, 
    enum: ['COD', 'Credit Card', 'PayPal', 'Bank Transfer', 'Wallet'], 
    required: true 
  },
  paymentStatus: {
    type: String,
    enum: ['Pending', 'Completed', 'Failed', 'Refunded'],
    default: 'Pending'
  },
  shippingAddress: {
    type: {
      line1: { type: String, required: true },
      line2: { type: String },
      city: { type: String, required: true },
      state: { type: String, required: true },
      postalCode: { type: String, required: true },
      country: { type: String, required: true },
      contactNumber: { type: String, required: true }
    },
    required: true
  },
  trackingNumber: {
    type: String,
    index: true
  },
  couponUsed: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Coupon'
  },
  notes: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual population for easier access to product details
OrderSchema.virtual('productDetails', {
  ref: 'Product',
  localField: 'items.product',
  foreignField: '_id',
  justOne: false
});

// Indexes
OrderSchema.index({ user: 1, status: 1 });
OrderSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Order', OrderSchema);