const mongoose = require('mongoose');
const PaymentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
    paymentMethod: { type: String, required: true }, // e.g., Stripe, Razorpay
    paymentStatus: { type: String, enum: ['Success', 'Failed', 'Pending'], default: 'Pending' },
    transactionId: { type: String, unique: true },
    amount: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
  });
  
  module.exports = mongoose.model('Payment', PaymentSchema); // Export the Payment model for use in other files.
  